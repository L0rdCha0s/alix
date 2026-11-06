#!/usr/bin/env python3
"""Run the native perf app via the existing isolated QEMU launcher, or compare reports."""
import argparse
import contextlib
import csv
import hashlib
import json
from pathlib import Path
import socketserver
import subprocess
import sys
import threading
import os
import time
import statistics
import re
import struct
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tests"))


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while block := self.request.recv(65536):
                self.request.sendall(block)
        except (TimeoutError, ConnectionError, OSError):
            pass


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, endpoint = self.request
        endpoint.sendto(data, self.client_address)


@contextlib.contextmanager
def echo_servers(port=0, bind="127.0.0.1"):
    class Tcp(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    class Udp(socketserver.ThreadingUDPServer):
        allow_reuse_address = True
        daemon_threads = True
    with Tcp((bind, port), TcpEcho) as tcp:
        with Udp((bind, tcp.server_address[1]), UdpEcho) as udp:
            threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (tcp, udp)]
            for thread in threads:
                thread.start()
            try:
                yield tcp.server_address[1]
            finally:
                tcp.shutdown()
                udp.shutdown()
                for thread in threads:
                    thread.join()


RESULT_FIELDS = "group name status samples workers operations bytes elapsed_ns p50_ns p95_ns max_ns user_us system_us minor_faults major_faults error".split()
PARALLEL_CASES = {"cpu_work_1", "cpu_work_n", "cpu_work_2n", "atomic_contended_n",
                  "mutex_contended_n", "malloc_contended_n", "yield_same_cpu_n",
                  "yield_spread_n", "pread_parallel_n"}
KERNEL_COUNTERS = [
    (f"tcp_{direction}_{name}", f"{symbol}[{index}]")
    for index, direction in enumerate(("read", "write"))
    for name, symbol in (("capture_calls", "g_user_tcp_capture_calls"),
                         ("capture_bytes", "g_user_tcp_capture_bytes"),
                         ("request_bytes", "g_user_tcp_request_bytes"),
                         ("completed_bytes", "g_io_tcp_completed_bytes"),
                         ("wouldblock", "g_io_tcp_wouldblock"))
] + [
    ("directory_next_requests", "g_io_directory_next_requests"),
    ("directory_next_inline", "g_io_directory_next_inline"),
    ("directory_worker_submits", "g_io_directory_worker_submits"),
    ("vfs_pread_calls", "g_user_storage_operations[IO_VFS_PREAD]"),
    ("vfs_pread_inline", "g_user_file_inline_storage[IO_VFS_PREAD]"),
    ("vfs_path_stat_calls", "g_user_storage_operations[IO_VFS_PATH_INFO]"),
    ("vfs_path_stat_inline", "g_user_file_inline_storage[IO_VFS_PATH_INFO]"),
    ("vfs_fd_stat_calls", "g_user_storage_operations[IO_VFS_STAT_INFO]"),
    ("vfs_fd_stat_inline", "g_user_file_inline_storage[IO_VFS_STAT_INFO]"),
    ("io_admission_restarts", "g_io_admission_restarts"),
    ("io_admission_restart_ticks", "g_io_admission_restart_ticks"),
    ("futex_registrations", "g_futex_wait_registrations"),
    ("futex_wake_calls", "g_futex_wake_calls"),
    ("futex_wake_candidates", "g_futex_wake_candidates"),
    ("futex_woken", "g_futex_woken"),
    ("futex_memory_retries", "g_futex_memory_busy_retries"),
    ("futex_slow_read_reused", "g_futex_slow_read_reused"),
    ("futex_epoch_retries", "g_futex_epoch_retries"),
    ("scheduler_switches", "g_scheduler_switch_count"),
    ("framebuffer_flush_calls", "g_video_flush_calls"),
    ("framebuffer_flush_bytes", "g_video_flush_bytes"),
    ("framebuffer_flush_ticks", "g_video_flush_ticks"),
    ("framebuffer_flush_max_ticks", "g_video_flush_max_ticks"),
] + [(f"futex_cpu{cpu}_{name}", f"{symbol}[{cpu}]") for cpu in range(4)
     for name,symbol in (("resumes","g_futex_resume_count"),("resume_ticks","g_futex_resume_ticks"),
                         ("resume_max_ticks","g_futex_resume_max_ticks"))]



def host_observation():
    try:load=list(os.getloadavg())
    except OSError:load=None
    return dict(utc=datetime.now(timezone.utc).isoformat(),logical_cpus=os.cpu_count(),load_average=load)


def sample_statistics(samples,quantum):
    grouped={}
    for sample in samples:
        if sample["operations"]>0:grouped.setdefault(sample["name"],[]).append(sample)
    out={}
    for name,rows in grouped.items():
        values=[row["elapsed_ns"]/row["operations"] for row in rows]
        low=min(max(0,row["elapsed_ns"]-quantum)/row["operations"] for row in rows)
        high=max((row["elapsed_ns"]+quantum)/row["operations"] for row in rows)
        out[name]=dict(samples=len(rows),median_ns=statistics.median(values),min_ns=min(values),max_ns=max(values),observed_range_with_tick_margin_ns=[low,high])
    return out


def scheduler_commands():
    fields=("lock_calls","lock_wait_tsc","pick_calls","pick_tsc","prepare_calls","prepare_tsc",
            "finish_calls","finish_tsc","deferred_calls","deferred_tsc","validation_calls","validation_tsc",
            "fpu_calls","fpu_tsc","mmu_calls","mmu_tsc","cr3_writes","msr_calls","msr_tsc","stack_calls","stack_walks","stack_tsc")
    cost_command='printf "PERF_SCHED_COST,tid=%llu,'+','.join(field+'=%llu' for field in fields)+'\\n", $thread->tid, '+', '.join('$thread->scheduler_cost.'+field for field in fields)
    return (
        "add-symbol-file " + str(ROOT / "build/alix.elf"),
        'printf "PERF_SCHED_OWNER,%llu\\n", g_perf_handoff->owner_pid',
        'printf "PERF_SCHED_STACK_MODES,%u\\n", g_scheduler_stack_protection_modes',
        "set $thread = g_thread_registry_head",
        "set $seen = 0",
        "while $thread && $seen < 512",
        'printf "PERF_SCHED_THREAD,tid=%llu,pid=%llu,state=%u,priority=%u,base=%u,override=%u,override_active=%u,affinity=%u,cpu=%u,running=%u,queued=%u,rq=%u,sleeping=%u,runtime=%llu,name=%s\\n", $thread->tid, $thread->owner_pid, $thread->state, $thread->priority, $thread->base_priority, $thread->priority_override, $thread->priority_override_active, $thread->affinity_enabled, $thread->affinity_cpu, $thread->running_cpu, $thread->in_run_queue, $thread->run_queue_cpu, $thread->sleeping, $thread->runtime_ticks, $thread->name',
        "if $thread->owner_pid == g_perf_handoff->owner_pid",
        cost_command,
        "end",
        "set $thread = $thread->registry_next",
        "set $seen = $seen + 1",
        "end",
        "set $cpu = 0",
        "while $cpu < 8",
        "set $current = g_current_threads[$cpu]",
        "if $current",
        'printf "PERF_SCHED_CPU,cpu=%u,tid=%llu,priority=%u,ready=%u,switches=%llu,name=%s\\n", $cpu, $current->tid, $current->priority, g_run_queues[$cpu].total, g_cpu_switch_counts[$cpu], $current->name',
        "end",
        "set $cpu = $cpu + 1",
        "end",
    )


def scheduler_snapshot(path):
    result = {"threads": [], "cpus": [], "costs": []}
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("PERF_SCHED_OWNER,"):
            result["owner_pid"] = int(line.split(",", 1)[1])
        elif line.startswith("PERF_SCHED_STACK_MODES,"):
            result["stack_protection_modes"]=int(line.split(",",1)[1])
        elif line.startswith(("PERF_SCHED_THREAD,", "PERF_SCHED_CPU,", "PERF_SCHED_COST,")):
            tag, *fields = next(csv.reader([line]))
            row = {}
            for field in fields:
                key, value = field.split("=", 1)
                row[key] = value if key == "name" else int(value)
            result[{"PERF_SCHED_THREAD":"threads","PERF_SCHED_CPU":"cpus","PERF_SCHED_COST":"costs"}[tag]].append(row)
    return result


def parse_log(path):
    data = {"metadata": {}, "results": [], "samples": [], "ui": {}, "ui_workloads": {}, "exports": [], "details": {}, "present_batches": [], "fairness": [], "handoff_ids": [], "complete": False}
    # Serial output may prefix a record with unrelated kernel diagnostics.
    for line in path.read_text(errors="replace").splitlines():
        if "PERF_" not in line:
            continue
        line = line[line.index("PERF_"):]
        # Kernel serial diagnostics have their own timestamp prefix.
        line = line.split("[", 1)[0]
        values = next(csv.reader([line]))
        tag, fields = values[0], values[1:]
        if tag == "PERF_META" and len(fields) >= 2:
            data["metadata"][fields[0]] = ",".join(fields[1:])
        elif tag == "PERF_RESULT" and len(fields) == len(RESULT_FIELDS):
            row = dict(zip(RESULT_FIELDS, fields))
            row.update({name: int(row[name]) for name in RESULT_FIELDS[3:]})
            data["results"].append(row)
        elif tag == "PERF_SAMPLE" and len(fields) == 4:
            data["samples"].append(dict(name=fields[0], sample=int(fields[1]), operations=int(fields[2]), elapsed_ns=int(fields[3])))
        elif tag == "PERF_HANDOFF_IDS" and len(fields) == 3:
            data["handoff_ids"].append(dict(sample=int(fields[0]),coordinator_tid=int(fields[1]),partner_tid=int(fields[2])))
        elif tag == "PERF_FAIRNESS" and len(fields) == 4:
            data["fairness"].append(dict(name=fields[0], sample=int(fields[1]),
                min_operations=int(fields[2]), max_operations=int(fields[3])))
        elif tag in ("PERF_UI", "PERF_UI_WORKLOAD") and len(fields) == 7:
            collection = "ui" if tag == "PERF_UI" else "ui_workloads"
            data[collection][f"{fields[0]}.{fields[1]}"] = dict(zip(
                ("count", "mean_ns", "p50_ns", "p95_ns", "max_ns"), map(int, fields[2:])))
        elif tag == "PERF_GUI_READY":
            for value in fields:
                key,number=value.split("=",1)
                data["metadata"]["ui_"+key]=number
        elif tag == "PERF_UI_PRESENT_BATCH" and len(fields)==4:
            data["present_batches"].append(dict(phase=fields[0],sample=int(fields[1]),operations=int(fields[2]),elapsed_ns=int(fields[3])))
        elif tag == "PERF_DETAIL" and len(fields) >= 2:
            data["details"][fields[0]] = ",".join(fields[1:])
        elif tag == "PERF_EXPORT" and len(fields) == 2:
            data["exports"].append({"path": fields[0], "status": int(fields[1].split("=", 1)[1])})
        elif tag == "PERF_DONE":
            data["complete"] = True
            data["completion"] = dict(field.split("=", 1) for field in fields)
        elif tag == "PERF_GUI_DONE":
            data["gui_completion"] = dict(field.split("=", 1) for field in fields)
    receipt = path.with_suffix(".boot-image.json")
    if receipt.exists():
        data["images"] = json.loads(receipt.read_text())
    quantum=int(data["metadata"].get("clock_resolution_ns","10000000"))
    data["sample_stats"]=sample_statistics(data["samples"],quantum)
    data["present_summary"]={}
    for phase in ("idle","load"):
        rows=[row for row in data["present_batches"] if row["phase"]==phase and row["operations"]>0]
        if rows:
            operations=sum(row["operations"] for row in rows);elapsed=sum(row["elapsed_ns"] for row in rows)
            values=[row["elapsed_ns"]/row["operations"] for row in rows]
            data["present_summary"][phase]=dict(batches=len(rows),operations=operations,elapsed_ns=elapsed,mean_ns_per_present=elapsed/operations,median_ns_per_present=statistics.median(values))
    data["log_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return data


def run(args):
    from cpp_runtime_qemu_test import run_native_elf
    for name,low,high in (("rounds",1,15),("duration",10,1000),("threads",1,32),("present_batch",1,128)):
        value=getattr(args,name)
        if value is not None and not low<=value<=high:raise ValueError(f"{name} must be {low}..{high}")
    if args.capture and not args.gui:raise ValueError("--capture requires --gui")
    subprocess.run(["make"], cwd=ROOT, check=True)
    if sum((args.capture, args.kernel_profile, args.scheduler_profile, args.scheduler_costs)) > 1:
        raise ValueError("choose one capture/profile mode")
    if (args.scheduler_profile or args.scheduler_costs) and args.case not in ("condition_pingpong", "condition_pingpong_2_3"):
        raise ValueError("--scheduler-profile requires --case condition_pingpong")
    if args.present_batch and args.present_batch>1 and (not args.gui or args.ui_present not in ("static","bottom")):
        raise ValueError("batched presents require --gui and --ui-present static or bottom")
    if args.exercise_stop and not (args.gui and args.capture):
        raise ValueError("--exercise-stop requires --gui --capture")
    args.output.mkdir(parents=True, exist_ok=True)
    arguments = ["--gui" if args.gui else "--cli"]
    if args.gui:
        arguments += ["--autorun", "--exit-when-done"]
    if args.quick:
        arguments += ["--quick"]
    if args.group:
        arguments += ["--group", args.group]
    if args.case:
        arguments += ["--case", args.case]
    if args.present_batch:
        arguments += ["--present-batch",str(args.present_batch)]
    if args.ui_present:
        arguments += ["--ui-present", args.ui_present]
    if args.workdir:
        arguments += ["--workdir", args.workdir]
    if args.rounds:
        arguments += ["--rounds", str(args.rounds)]
    if args.duration:
        arguments += ["--duration", str(args.duration)]
    if args.threads:
        arguments += ["--threads", str(args.threads)]
    log = args.output / "serial.log"
    binary = ROOT / "build/user/runtime/perf.elf"
    image = args.output / "dashboard.ppm"
    options = {}
    if args.gui and args.capture:
        options.update(user_breakpoint=("perf_gui_visual_checkpoint", ROOT / "build/user/perf.elf",
                       ("monitor screendump " + str(image.resolve()),)),
                       after_breakpoint_commands=("sendkey p 80", "mouse_move 12 8", "sendkey e 80") + (("sendkey spc 80",) if args.exercise_stop else ()))
    if args.kernel_profile:
        if not args.case:raise ValueError("--kernel-profile requires one --case")
        options["user_breakpoint"]=("perf_record", ROOT / "build/user/perf.elf", (
            "add-symbol-file " + str(ROOT / "build/alix.elf"),
            "p g_irq_deferred_count", "p g_irq_rx_count", "p g_poll_rx_count",
            "p g_deferred_poll_count", "p g_watchdog_poll_count",
            "p g_user_file_inline_poll", "p g_user_file_inline_socket",
            "p g_vm_serial_waits", "p g_vm_tlb_waits",
            "p g_syscall_poll_count", "p g_deferred_wake_ticks", "p g_deferred_wake_runs") + tuple(
                f'printf "PERF_KERNEL_COUNTER,{name},%llu\\n", {expression}'
                for name, expression in KERNEL_COUNTERS))
    if args.scheduler_profile:
        options["user_breakpoint"] = ("perf_handoff_ready_checkpoint", ROOT / "build/user/perf.elf",
                                      scheduler_commands())
    if args.scheduler_costs:
        options["user_breakpoint"] = ("perf_handoff_ready_checkpoint", ROOT / "build/user/perf.elf",
            ("add-symbol-file " + str(ROOT/"build/alix.elf"), "set var g_sched_cost_control.enabled = 1"),
            ("perf_handoff_sample_checkpoint", ("set var g_sched_cost_control.enabled = 0",) + scheduler_commands()))
    if args.pcap:
        options["pcap_path"] = args.output / "network.pcap"
    expected_metadata=dict(mode="gui" if args.gui else "cli",rounds=str(args.rounds if args.rounds is not None else 3 if args.quick else 5),
        duration_ms=str(args.duration if args.duration is not None else 10 if args.quick else 30),case=args.case or "all",group=args.group or "all",
        workdir=args.workdir or "/tmp",ui_present=args.ui_present or "dashboard",ui_present_batch=str(args.present_batch or 1))
    evaluator_paths={"driver":ROOT/"tools/perf.py","launcher":ROOT/"tests/cpp_runtime_qemu_test.py"}
    evaluator_hashes={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in evaluator_paths.items()}
    observation_before=host_observation()
    wall_before=time.monotonic()
    kernel_before=hashlib.sha256((ROOT/"build/alix.elf").read_bytes()).hexdigest()
    app_before=hashlib.sha256(binary.read_bytes()).hexdigest()
    error = None
    try:
        with echo_servers() as port:
            arguments += ["--net", "10.0.2.2", "--port", str(port)]
            expected_metadata["network"]="10.0.2.2:"+str(port)
            run_native_elf("runtime/perf.elf", ("PERF_GUI_DONE," if args.gui else "PERF_DONE,",), log,
                           "Native Alix performance run", timeout_seconds=args.timeout,
                           arguments=tuple(arguments), gui_launch=args.gui,
                           expected_wait_status=0, fail_on_missing_markers_at_exit=True,
                           **options)
    except Exception as exc:
        error = exc
    finally:
        if log.exists():
            report = parse_log(log)
            report["invocation"] = arguments
            expected_metadata["threads"]=str(args.threads if args.threads is not None else min(8,int(report["metadata"].get("cpus","0"))))
            report["requested_metadata"]=expected_metadata
            report["configuration_mismatches"]={key:dict(expected=value,actual=report["metadata"].get(key)) for key,value in expected_metadata.items() if report["metadata"].get(key)!=value}
            report["host_before"]=observation_before
            report["host_after"]=host_observation()
            report["host_elapsed_seconds"]=time.monotonic()-wall_before
            report["build_artifacts_changed_during_run"]=kernel_before!=hashlib.sha256((ROOT/"build/alix.elf").read_bytes()).hexdigest() or app_before!=hashlib.sha256(binary.read_bytes()).hexdigest()
            report["evaluator_sources"] = evaluator_hashes
            report["evaluator_sources_changed_during_run"] = any(
                hashlib.sha256(path.read_bytes()).hexdigest()!=evaluator_hashes[name] for name,path in evaluator_paths.items())
            report["environment"] = "8-CPU QEMU; disposable data disk; host loopback TCP/UDP echo"
            report["capture_perturbs_timing"] = bool(args.scheduler_profile or args.scheduler_costs or args.gui and (args.capture or args.kernel_profile))
            report["packet_capture"] = bool(args.pcap)
            report["kernel_profile_after_measurement"] = bool(args.kernel_profile)
            breakpoint_log=log.with_suffix(".breakpoint.txt")
            if (args.scheduler_profile or args.scheduler_costs) and breakpoint_log.exists():
                report["scheduler_snapshot"] = scheduler_snapshot(breakpoint_log)
                if len(report["scheduler_snapshot"]["cpus"]) != 8 and error is None:
                    error = RuntimeError("incomplete scheduler snapshot")
                ids=report.get("handoff_ids",[])
                snapshot=report["scheduler_snapshot"]
                report["scheduler_cost_profile"] = bool(args.scheduler_costs)
                if args.scheduler_costs:
                    report["scheduler_cost_units"] = "CPU-local TSC ticks"
                    if len(snapshot["costs"])<2 and error is None:error=RuntimeError("missing scheduler phase costs")
                owner_threads={row["tid"]:row for row in snapshot["threads"] if row["pid"]==snapshot.get("owner_pid")}
                wanted=(0,1) if args.case=="condition_pingpong" else (2,3)
                if ids and error is None:
                    pair=(ids[0]["coordinator_tid"],ids[0]["partner_tid"])
                    if any(tid not in owner_threads or not owner_threads[tid]["affinity"] or
                           owner_threads[tid]["cpu"]!=cpu for tid,cpu in zip(pair,wanted)):
                        error=RuntimeError("scheduler snapshot does not match the actual handoff endpoints")
                elif error is None:
                    error=RuntimeError("missing handoff identity records for scheduler snapshot")
            if args.kernel_profile and breakpoint_log.exists():
                report["kernel_counters"]={key:int(value) for key,value in re.findall(
                    r"PERF_KERNEL_COUNTER,([a-z_0-9]+),(\d+)",breakpoint_log.read_text(errors="replace"))}
                if len(report["kernel_counters"])!=len(KERNEL_COUNTERS) and error is None:
                    error=RuntimeError("incomplete kernel counter capture")
            report["launcher_error"] = str(error) if error else None
            (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            with (args.output / "results.csv").open("w") as target:
                writer = csv.DictWriter(target, fieldnames=RESULT_FIELDS)
                writer.writeheader()
                writer.writerows(report["results"])
            print(f"Results: {args.output / 'report.json'}")
            for row in report["results"]:
                if row["status"] != "OK":
                    print(f"  {row['status']:4} {row['name']} (error {row['error']})")
            if image.exists():
                subprocess.run(["sips", "-s", "format", "png", str(image), "--out", str(image.with_suffix('.png'))], stdout=subprocess.DEVNULL, check=True)
    if error:
        raise error
    if report.get("configuration_mismatches"):
        raise RuntimeError("guest configuration differs from requested arguments: "+json.dumps(report["configuration_mismatches"]))
    if report.get("build_artifacts_changed_during_run"):
        raise RuntimeError("build artifacts changed during the measurement")
    if report.get("evaluator_sources_changed_during_run"):
        raise RuntimeError("evaluation driver or launcher changed during the run")
    if len(report["results"]) != int(report.get("completion",{}).get("results","-1")):
        raise RuntimeError("incomplete result records in serial capture")
    if not report["results"]:
        raise RuntimeError("no workload matched the selectors")
    if report.get("completion",{}).get("stopped")!="1" and report["metadata"].get("minimum_sample_ticks"):
        target=max(int(report["metadata"]["duration_ms"])*1000000,
                   int(report["metadata"]["clock_resolution_ns"])*int(report["metadata"]["minimum_sample_ticks"]))
        short=[row for row in report["samples"] if row["elapsed_ns"]<target]
        if short:raise RuntimeError("samples shorter than requested clock floor: "+json.dumps(short))
    for result in report["results"]:
        if result["name"] in PARALLEL_CASES and result["status"]=="OK":
            rows=[row for row in report["fairness"] if row["name"]==result["name"]]
            if len(rows)!=result["samples"]:raise RuntimeError("missing worker progress records: "+result["name"])
    if args.gui and report.get("gui_completion",{}).get("error","0")!="0":
        raise RuntimeError("GUI reported an event/presentation failure")
    if report.get("completion",{}).get("stopped")=="1" and not args.exercise_stop:
        raise RuntimeError("unattended benchmark stopped before completion")
    if any(row["status"] == "FAIL" for row in report["results"]) or not report["complete"]:
        return 1
    if args.gui and not any(item["status"] == 0 for item in report["exports"]):
        raise RuntimeError("GUI export did not complete")
    if args.gui and args.capture and int(report.get("gui_completion", {}).get("probes", "0")) < 1:
        raise RuntimeError("GUI did not receive the injected input probe")
    if args.exercise_stop and report.get("completion", {}).get("stopped") != "1":
        raise RuntimeError("GUI did not process the Stop input")
    return 0


def compare(args):
    before = json.loads(args.before.read_text())
    after = json.loads(args.after.read_text())
    for report in (before,after):
        if report.get("configuration_mismatches"):
            print("A guest did not receive its requested arguments; repeat the run.",file=sys.stderr)
            return 2
        if "group" not in report["metadata"]:
            invocation=report.get("invocation",[])
            report["metadata"]["group"]=invocation[invocation.index("--group")+1] if "--group" in invocation else "all"
        report.setdefault("sample_stats",sample_statistics(report.get("samples",[]),int(report["metadata"].get("clock_resolution_ns","10000000"))))
    for report,path in ((before,args.before),(after,args.after)):
        if report["metadata"].get("mode")=="gui" and "ui_width" not in report["metadata"]:
            serial=path.parent/"serial.log"
            if serial.exists():
                import re
                found=re.search(r"PERF_GUI_READY,width=(\d+),height=(\d+)",serial.read_text(errors="replace"))
                if found:report["metadata"].update(ui_width=found.group(1),ui_height=found.group(2))
    for key in ("mode", "cpus", "threads", "rounds", "duration_ms", "workdir", "clock", "case", "group", "ui_present", "ui_present_batch", "ui_width", "ui_height"):
        default = "all" if key in ("case","group") else "dashboard" if key == "ui_present" else "1" if key=="ui_present_batch" else None
        if before["metadata"].get(key, default) != after["metadata"].get(key, default):
            print(f"Configuration differs: {key}: {before['metadata'].get(key)} -> {after['metadata'].get(key)}", file=sys.stderr)
            return 2
    if before.get("build_artifacts_changed_during_run") or after.get("build_artifacts_changed_during_run"):
        print("A build changed artifacts during a run; repeat without concurrent builds.",file=sys.stderr)
        return 2
    if before.get("evaluator_sources_changed_during_run") or after.get("evaluator_sources_changed_during_run"):
        print("Evaluation sources changed during a run; repeat with stable tools.",file=sys.stderr)
        return 2
    if before.get("evaluator_sources") and after.get("evaluator_sources") and before["evaluator_sources"]!=after["evaluator_sources"]:
        print("Evaluation driver or launcher differs; repeat the baseline with matching tools.",file=sys.stderr)
        return 2
    if before.get("capture_perturbs_timing") or after.get("capture_perturbs_timing"):
        print("Capture pauses perturb timings; use uncaptured runs for comparisons.", file=sys.stderr)
        return 2
    if not before.get("complete") or not after.get("complete") or before.get("launcher_error") or after.get("launcher_error") or before.get("completion", {}).get("stopped") == "1" or after.get("completion", {}).get("stopped") == "1" or before.get("completion", {}).get("failed") != "0" or after.get("completion", {}).get("failed") != "0":
        print("Both reports must be complete successful runs.", file=sys.stderr)
        return 2
    if before.get("packet_capture", False) != after.get("packet_capture", False):
        print("Packet capture settings differ.", file=sys.stderr)
        return 2
    names={r["name"] for report in (before,after) for r in report["results"]}
    protocols={"condition_protocol":{"condition_pingpong","condition_pingpong_2_3"},"parallel_protocol":PARALLEL_CASES}
    for key,cases in protocols.items():
        if names & cases and before["metadata"].get(key)!=after["metadata"].get(key):
            print(f"Measurement protocol differs: {key}; repeat the baseline with the current app.",file=sys.stderr)
            return 2
    old = {r["name"]: r for r in before["results"] if r["status"] == "OK"}
    print(f"{'workload':34} {'before us/op':>14} {'after us/op':>14} {'change':>10}  observed ranges")
    for new in after["results"]:
        prev = old.get(new["name"])
        if new["status"] != "OK" or not prev or not prev["p50_ns"]:
            continue
        change = (new["p50_ns"] / prev["p50_ns"] - 1) * 100
        a_stats=before.get("sample_stats",{}).get(new["name"])
        b_stats=after.get("sample_stats",{}).get(new["name"])
        overlap="unavailable"
        if a_stats and b_stats:
            a_lo,a_hi=a_stats["observed_range_with_tick_margin_ns"];b_lo,b_hi=b_stats["observed_range_with_tick_margin_ns"]
            overlap="overlap" if max(a_lo,b_lo)<=min(a_hi,b_hi) else "separate"
        print(f"{new['name']:34} {prev['p50_ns']/1000:14.3f} {new['p50_ns']/1000:14.3f} {change:+9.1f}%  {overlap}")
    if int(after["metadata"].get("ui_present_batch","1"))>1:
        print("Batched-present experiment: frame/input intervals include intentional upload batches.")
    for phase in sorted(before.get("present_summary",{}).keys() & after.get("present_summary",{}).keys()):
        a=before["present_summary"][phase];b=after["present_summary"][phase]
        print(f"Present {phase}: mean {a['mean_ns_per_present']/1e6:.3f} -> {b['mean_ns_per_present']/1e6:.3f} ms/call ({a['operations']}/{b['operations']} uploads)")
    for name in sorted(before.get("ui", {}).keys() & after.get("ui", {}).keys()):
        a, b = before["ui"][name], after["ui"][name]
        print(f"UI {name}: p95 {a['p95_ns']/1e6:.0f} -> {b['p95_ns']/1e6:.0f} ms (n={a['count']}/{b['count']})")
    return 0


def analyze_zen_stalls(args):
    directory = args.run.resolve(strict=True)
    symbols = args.xul_symbols.resolve(strict=True)
    output = args.output or directory / "stall-summary.json"
    if output.exists():
        raise RuntimeError(f"existing analysis preserved: {output}")
    result = json.loads((directory / "result.json").read_text())
    before = symbols.stat()
    notes = subprocess.check_output(["x86_64-elf-readelf", "-n", str(symbols)], text=True)
    identities = set(re.findall(r"Build ID:\s*([0-9a-f]+)", notes))
    if len(identities) != 1:
        raise RuntimeError("symbols need one GNU build ID")
    identity = identities.pop()
    rows, captures, saved, saved_render = [], [], 0, 0
    with symbols.open("rb") as elf:
        header = elf.read(64)
        if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", header, 18)[0] != 62:
            raise RuntimeError("symbols must be a little-endian x86-64 ELF")
        offset = struct.unpack_from("<Q", header, 32)[0]
        width, count = struct.unpack_from("<HH", header, 54)
        if width != 56 or not 0 < count <= 1024 or offset + width * count > before.st_size:
            raise RuntimeError("invalid symbol ELF program headers")
        elf.seek(offset)
        segments = [struct.unpack("<IIQQQQQQ", elf.read(width)) for _ in range(count)]
        for record in result.get("stall_profiles", []):
            if not isinstance(record.get("snapshot"), str):
                raise RuntimeError("incomplete stall capture has no snapshot")
            snapshot_path = (directory / record["snapshot"]).resolve(strict=True)
            if snapshot_path.parent != directory:
                raise RuntimeError("stall snapshot must belong to its run")
            snapshot = json.loads(snapshot_path.read_text())
            saved_render += len(snapshot.get("render_contexts", []))
            captures.append(snapshot_path.name)
            for cpu in snapshot["cpus"]:
                location = cpu.get("user_location")
                if not location or not location["module"].endswith("/libxul.so"):
                    continue
                if cpu.get("user_context_source") != "live_registers":
                    saved += 1
                    continue
                if location.get("build_id") != identity:
                    raise RuntimeError("live module build ID differs from supplied symbols")
                probe = cpu.get("user_code_probe")
                if not probe or int(probe["address"], 16) != int(location["address"], 16):
                    raise RuntimeError("live PC lacks its instruction-byte probe")
                address = int(location["offset"], 16)
                expected = bytes.fromhex(probe["code_hex"])
                segment = next((s for s in segments if s[0] == 1 and s[1] & 1 and
                                s[3] <= address and address + len(expected) <= s[3] + s[5]), None)
                if not expected or not segment:
                    raise RuntimeError("live PC is outside executable file bytes")
                elf.seek(segment[2] + address - segment[3])
                if elf.read(len(expected)) != expected:
                    raise RuntimeError(f"live instruction bytes differ at {hex(address)}")
                rows.append({"capture": snapshot_path.name, "cpu": cpu["cpu"],
                             "thread": cpu["name"], "pid": cpu["pid"], "tid": cpu["tid"],
                             "offset": hex(address), "instruction_bytes_verified": len(expected)})
        elf.seek(0)
        digest = hashlib.file_digest(elf, "sha256").hexdigest()
    addresses = sorted({int(row["offset"], 16) for row in rows})
    frames = {}
    if addresses:
        resolved = subprocess.run(["x86_64-elf-addr2line", "-a", "-f", "-C", "-i", "-e", str(symbols)],
            input="".join(hex(address) + "\n" for address in addresses), text=True,
            capture_output=True, check=True, timeout=240).stdout.splitlines()
        current = None
        for line in resolved:
            if re.fullmatch(r"0x[0-9a-fA-F]+", line):
                current = int(line, 16)
                frames[current] = []
            elif current is not None:
                frames[current].append(line)
    groups = {}
    for row in rows:
        lines = frames.get(int(row["offset"], 16), [])
        if len(lines) % 2 or not lines:
            raise RuntimeError("incomplete addr2line result")
        row["frames"] = [{"function": lines[i], "source": lines[i + 1]} for i in range(0, len(lines), 2)]
        key = (row["thread"], lines[0])
        groups[key] = groups.get(key, 0) + 1
    after = symbols.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        raise RuntimeError("symbols changed during analysis")
    report = {"run": str(directory), "symbols": str(symbols), "symbols_sha256": digest,
              "build_id": identity, "captures": captures, "saved_cpu_contexts_excluded": saved,
              "saved_render_contexts_excluded": saved_render,
              "method": "one live snapshot per stalled probe; diagnostic counts are not CPU percentages",
              "capture_perturbs_timing": result.get("capture_perturbs_timing"),
              "groups": [{"thread": thread, "function": function, "samples": count}
                         for (thread, function), count in sorted(groups.items(), key=lambda item: -item[1])],
              "samples": rows, "analyzer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as destination:
        json.dump(report, destination, indent=2)
        destination.write("\n")
    print(f"Verified {len(rows)} live libxul PCs across {len(captures)} captures: {output}")
    for row in report["groups"]:
        print(f"{row['samples']:3} {row['thread']}: {row['function']}")
    return 0


def swgl_profile_info(args):
    symbols = args.xul_symbols.resolve(strict=True)
    if args.output.exists():
        raise RuntimeError(f"existing profile metadata preserved: {args.output}")
    before = symbols.stat()
    identities = set(re.findall(r"Build ID:\s*([0-9a-f]+)", subprocess.check_output(
        ["x86_64-elf-readelf", "-n", str(symbols)], text=True)))
    if len(identities) != 1:
        raise RuntimeError("symbols need one GNU build ID")
    commands = r'''
import gdb, json
def layout(typename, fields):
    result = {}
    for name, kind in fields.items():
        expression = "((" + typename + "*)0)->" + name
        result[name] = {"offset": int(gdb.parse_and_eval("(unsigned long long)&(" + expression + ")")),
                        "size": int(gdb.parse_and_eval("sizeof(" + expression + ")")), "kind": kind}
    return result
fragment = layout("glsl::FragmentShaderImpl", {"run_func": "ptr", "draw_span_RGBA8_func": "ptr",
    "draw_span_R8_func": "ptr", "flags": "uint", "swgl_SpanLength": "int"})
blur_fields = {"sColor0": "ptr", "vUv": "floats", "vUvRect": "floats", "vUvClampRect": "floats",
               "vOffsetScale": "floats", "vSupport": "ints", "vGaussCoefficients": "floats"}
blur = layout("cs_blur_COLOR_TARGET_frag", blur_fields)
if blur != layout("cs_blur_ALPHA_TARGET_frag", blur_fields):
    raise RuntimeError("blur variants have different layouts")
sampler = layout("glsl::sampler2D_impl", {"buf": "ptr", "stride": "int", "width": "int",
    "height": "int", "format": "uint", "filter": "uint"})
format_type = gdb.parse_and_eval("((glsl::sampler2D_impl*)0)->format").type.strip_typedefs()
info = {"fragment_shader_offset": int(gdb.parse_and_eval("(unsigned long long)&fragment_shader")),
        "fragment": fragment, "blur": blur, "sampler": sampler,
        "texture_formats": {str(field.enumval): field.name for field in format_type.fields()}}
print("SWGL_PROFILE_INFO " + json.dumps(info))
'''
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="swgl-layout-", dir=args.output.parent) as temporary:
        script = Path(temporary) / "layout.gdb"
        script.write_text("set pagination off\nset language c++\npython\n" + commands + "\nend\n")
        result = subprocess.run(["x86_64-elf-gdb", "-nx", "-q", "-batch", "-ex",
            "file " + json.dumps(str(symbols)), "-x", str(script)], text=True,
            capture_output=True, timeout=180)
        if result.returncode:
            raise RuntimeError("GDB SWGL layout extraction failed: " +
                               (result.stderr + result.stdout)[-3000:].strip())
    match = re.search(r"^SWGL_PROFILE_INFO (.*)$", result.stdout, re.M)
    if not match:
        raise RuntimeError("GDB did not return SWGL layout metadata")
    info = json.loads(match.group(1))
    for group in ("fragment", "blur", "sampler"):
        for field in info[group].values():
            if not 0 <= field["offset"] < 4096 or not 0 < field["size"] <= 128:
                raise RuntimeError("SWGL field exceeds bounded capture layout")
    nm = subprocess.check_output(["x86_64-elf-nm", "-S", "--defined-only", str(symbols)], text=True)
    ranges = []
    for line in nm.splitlines():
        parts = line.split()
        if len(parts) == 4 and re.fullmatch(r"_ZN25cs_blur_(ALPHA|COLOR)_TARGET_frag3runEPN4glsl18FragmentShaderImplE", parts[3]):
            start, size = int(parts[0], 16), int(parts[1], 16)
            ranges.append([start, start + size])
    if len(ranges) != 2:
        raise RuntimeError("matching blur run symbols not found")
    with symbols.open("rb") as elf:
        header = elf.read(64)
        if header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", header, 18)[0] != 62:
            raise RuntimeError("SWGL metadata requires x86-64 ELF")
        offset = struct.unpack_from("<Q", header, 32)[0]
        width, count = struct.unpack_from("<HH", header, 54)
        if width != 56 or not 0 < count <= 1024:
            raise RuntimeError("invalid SWGL ELF program headers")
        elf.seek(offset)
        segments = [struct.unpack("<IIQQQQQQ", elf.read(width)) for _ in range(count)]
        global_offset = info["fragment_shader_offset"]
        if not any(s[0] == 1 and s[1] & 2 and s[3] <= global_offset and global_offset + 8 <= s[3] + s[6] for s in segments):
            raise RuntimeError("SWGL current-shader pointer is not in writable module memory")
        if any(not any(s[0] == 1 and s[1] & 1 and s[3] <= low < high <= s[3] + s[5] for s in segments) for low, high in ranges):
            raise RuntimeError("SWGL blur function is not in executable module bytes")
        elf.seek(0)
        digest = hashlib.file_digest(elf, "sha256").hexdigest()
    after = symbols.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        raise RuntimeError("SWGL symbols changed while extracting layout")
    info.update(schema="alix_swgl_profile_v1", build_id=identities.pop(), symbols_sha256=digest,
                blur_run_ranges=ranges, generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    with args.output.open("x") as output:
        json.dump(info, output, indent=2)
        output.write("\n")
    print(f"SWGL profile metadata: {args.output} ({info['build_id']})")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run")
    r.add_argument("--gui", action="store_true")
    r.add_argument("--capture", action="store_true", help="capture dashboard and inject real probe keys; debugger pause invalidates baseline timing")
    r.add_argument("--exercise-stop", action="store_true", help="with --gui --capture: inject Stop after the visual checkpoint")
    r.add_argument("--quick", action="store_true")
    r.add_argument("--group")
    r.add_argument("--case")
    r.add_argument("--present-batch", type=int)
    r.add_argument("--ui-present", choices=("dashboard","static","bottom"))
    r.add_argument("--workdir")
    r.add_argument("--pcap", action="store_true")
    r.add_argument("--kernel-profile", action="store_true")
    r.add_argument("--scheduler-profile", action="store_true", help="capture active handoff priorities and CPU queues; excludes timing comparisons")
    r.add_argument("--scheduler-costs", action="store_true", help="arm CPU-local scheduler phase counters and capture the first completed handoff sample")
    r.add_argument("--rounds", type=int)
    r.add_argument("--duration", type=int)
    r.add_argument("--threads", type=int)
    r.add_argument("--timeout", type=int, default=240)
    r.add_argument("--output", type=Path, default=ROOT / "build/perf/latest")
    c = sub.add_parser("compare")
    c.add_argument("before", type=Path)
    c.add_argument("after", type=Path)
    z = sub.add_parser("analyze-zen-stalls", help="verify and symbolize completed native Zen stall captures")
    z.add_argument("run", type=Path)
    z.add_argument("--xul-symbols", type=Path, required=True, help="matching unstripped libxul ELF")
    z.add_argument("--output", type=Path, help="new summary file; defaults to RUN/stall-summary.json")
    s = sub.add_parser("swgl-profile-info", help="extract bounded SWGL capture layouts from matching native symbols")
    s.add_argument("--xul-symbols", type=Path, required=True)
    s.add_argument("--output", type=Path, required=True)
    e = sub.add_parser("serve", help="TCP and UDP echo for physical Alix machines")
    e.add_argument("--bind", default="0.0.0.0")
    e.add_argument("--port", type=int, default=7777)
    args = parser.parse_args()
    if args.command == "run":
        return run(args)
    if args.command == "compare":
        return compare(args)
    if args.command == "analyze-zen-stalls":
        return analyze_zen_stalls(args)
    if args.command == "swgl-profile-info":
        return swgl_profile_info(args)
    with echo_servers(args.port, args.bind) as port:
        print(f"TCP/UDP echo listening on {args.bind}:{port}", flush=True)
        threading.Event().wait()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        print(f"perf: {exc}", file=sys.stderr)
        sys.exit(1)
