/* Generated with mpmath 1.3.0 at 100 decimal digits. */
static bool math_vector_tests(void)
{
    CHECK(fesetround(FE_TONEAREST)==0);
    CHECK(close_to(acosf((float)-0.75L),2.41885840577637762728426603063816952217195091L,3e-6L));
    CHECK(close_to(acos((double)-0.75L),2.41885840577637762728426603063816952217195091L,1e-14L));
    CHECK(close_to(acosl((long double)-0.75L),2.41885840577637762728426603063816952217195091L,4e-18L));
    CHECK(close_to(acosf((float)-0.25L),1.82347658193697527271697912863346241435077843L,3e-6L));
    CHECK(close_to(acos((double)-0.25L),1.82347658193697527271697912863346241435077843L,1e-14L));
    CHECK(close_to(acosl((long double)-0.25L),1.82347658193697527271697912863346241435077843L,4e-18L));
    CHECK(close_to(acosf((float)0.0L),1.5707963267948966192313216916397514420985847L,3e-6L));
    CHECK(close_to(acos((double)0.0L),1.5707963267948966192313216916397514420985847L,1e-14L));
    CHECK(close_to(acosl((long double)0.0L),1.5707963267948966192313216916397514420985847L,4e-18L));
    CHECK(close_to(acosf((float)0.5L),1.04719755119659774615421446109316762806572313L,3e-6L));
    CHECK(close_to(acos((double)0.5L),1.04719755119659774615421446109316762806572313L,1e-14L));
    CHECK(close_to(acosl((long double)0.5L),1.04719755119659774615421446109316762806572313L,4e-18L));
    CHECK(close_to(acosf((float)0.875L),0.505360510284157306971314873987421944504387466L,3e-6L));
    CHECK(close_to(acos((double)0.875L),0.505360510284157306971314873987421944504387466L,1e-14L));
    CHECK(close_to(acosl((long double)0.875L),0.505360510284157306971314873987421944504387466L,4e-18L));
    CHECK(close_to(asinf((float)-0.75L),-0.848062078981481008052944338998418080073366213L,3e-6L));
    CHECK(close_to(asin((double)-0.75L),-0.848062078981481008052944338998418080073366213L,1e-14L));
    CHECK(close_to(asinl((long double)-0.75L),-0.848062078981481008052944338998418080073366213L,4e-18L));
    CHECK(close_to(asinf((float)-0.25L),-0.252680255142078653485657436993710972252193733L,3e-6L));
    CHECK(close_to(asin((double)-0.25L),-0.252680255142078653485657436993710972252193733L,1e-14L));
    CHECK(close_to(asinl((long double)-0.25L),-0.252680255142078653485657436993710972252193733L,4e-18L));
    CHECK(close_to(asinf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(asin((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(asinl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(asinf((float)0.5L),0.523598775598298873077107230546583814032861567L,3e-6L));
    CHECK(close_to(asin((double)0.5L),0.523598775598298873077107230546583814032861567L,1e-14L));
    CHECK(close_to(asinl((long double)0.5L),0.523598775598298873077107230546583814032861567L,4e-18L));
    CHECK(close_to(asinf((float)0.875L),1.06543581651073931226000681765232949759419723L,3e-6L));
    CHECK(close_to(asin((double)0.875L),1.06543581651073931226000681765232949759419723L,1e-14L));
    CHECK(close_to(asinl((long double)0.875L),1.06543581651073931226000681765232949759419723L,4e-18L));
    CHECK(close_to(atanf((float)-3.5L),-1.29249666778978526790309142140708168458531408L,3e-6L));
    CHECK(close_to(atan((double)-3.5L),-1.29249666778978526790309142140708168458531408L,1e-14L));
    CHECK(close_to(atanl((long double)-3.5L),-1.29249666778978526790309142140708168458531408L,4e-18L));
    CHECK(close_to(atanf((float)-0.25L),-0.244978663126864154172082481211275810914144098L,3e-6L));
    CHECK(close_to(atan((double)-0.25L),-0.244978663126864154172082481211275810914144098L,1e-14L));
    CHECK(close_to(atanl((long double)-0.25L),-0.244978663126864154172082481211275810914144098L,4e-18L));
    CHECK(close_to(atanf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(atan((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(atanl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(atanf((float)0.5L),0.463647609000806116214256231461214402028537054L,3e-6L));
    CHECK(close_to(atan((double)0.5L),0.463647609000806116214256231461214402028537054L,1e-14L));
    CHECK(close_to(atanl((long double)0.5L),0.463647609000806116214256231461214402028537054L,4e-18L));
    CHECK(close_to(atanf((float)8.0L),1.44644133224813518419996684247588041652541451L,3e-6L));
    CHECK(close_to(atan((double)8.0L),1.44644133224813518419996684247588041652541451L,1e-14L));
    CHECK(close_to(atanl((long double)8.0L),1.44644133224813518419996684247588041652541451L,4e-18L));
    CHECK(close_to(acoshf((float)1.0L),0.0L,3e-6L));
    CHECK(close_to(acosh((double)1.0L),0.0L,1e-14L));
    CHECK(close_to(acoshl((long double)1.0L),0.0L,4e-18L));
    CHECK(close_to(acoshf((float)1.25L),0.693147180559945309417232121458176568075500134L,3e-6L));
    CHECK(close_to(acosh((double)1.25L),0.693147180559945309417232121458176568075500134L,1e-14L));
    CHECK(close_to(acoshl((long double)1.25L),0.693147180559945309417232121458176568075500134L,4e-18L));
    CHECK(close_to(acoshf((float)2.0L),1.31695789692481670862504634730796844402698197L,3e-6L));
    CHECK(close_to(acosh((double)2.0L),1.31695789692481670862504634730796844402698197L,1e-14L));
    CHECK(close_to(acoshl((long double)2.0L),1.31695789692481670862504634730796844402698197L,4e-18L));
    CHECK(close_to(acoshf((float)8.0L),2.76865938331357383273200140938374551987205789L,3e-6L));
    CHECK(close_to(acosh((double)8.0L),2.76865938331357383273200140938374551987205789L,1e-14L));
    CHECK(close_to(acoshl((long double)8.0L),2.76865938331357383273200140938374551987205789L,4e-18L));
    CHECK(close_to(asinhf((float)-3.5L),-1.96572047164965152123875634867006930228369939L,3e-6L));
    CHECK(close_to(asinh((double)-3.5L),-1.96572047164965152123875634867006930228369939L,1e-14L));
    CHECK(close_to(asinhl((long double)-3.5L),-1.96572047164965152123875634867006930228369939L,4e-18L));
    CHECK(close_to(asinhf((float)-0.25L),-0.247466461547263452944781549788359289253766903L,3e-6L));
    CHECK(close_to(asinh((double)-0.25L),-0.247466461547263452944781549788359289253766903L,1e-14L));
    CHECK(close_to(asinhl((long double)-0.25L),-0.247466461547263452944781549788359289253766903L,4e-18L));
    CHECK(close_to(asinhf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(asinh((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(asinhl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(asinhf((float)0.5L),0.481211825059603447497758913424368423135184334L,3e-6L));
    CHECK(close_to(asinh((double)0.5L),0.481211825059603447497758913424368423135184334L,1e-14L));
    CHECK(close_to(asinhl((long double)0.5L),0.481211825059603447497758913424368423135184334L,4e-18L));
    CHECK(close_to(asinhf((float)8.0L),2.77647228072371767353080402702854345880282894L,3e-6L));
    CHECK(close_to(asinh((double)8.0L),2.77647228072371767353080402702854345880282894L,1e-14L));
    CHECK(close_to(asinhl((long double)8.0L),2.77647228072371767353080402702854345880282894L,4e-18L));
    CHECK(close_to(atanhf((float)-0.75L),-0.972955074527656652552676371721589864818542365L,3e-6L));
    CHECK(close_to(atanh((double)-0.75L),-0.972955074527656652552676371721589864818542365L,1e-14L));
    CHECK(close_to(atanhl((long double)-0.75L),-0.972955074527656652552676371721589864818542365L,4e-18L));
    CHECK(close_to(atanhf((float)-0.25L),-0.255412811882995341602757048151830967439055398L,3e-6L));
    CHECK(close_to(atanh((double)-0.25L),-0.255412811882995341602757048151830967439055398L,1e-14L));
    CHECK(close_to(atanhl((long double)-0.25L),-0.255412811882995341602757048151830967439055398L,4e-18L));
    CHECK(close_to(atanhf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(atanh((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(atanhl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(atanhf((float)0.5L),0.549306144334054845697622618461262852323745279L,3e-6L));
    CHECK(close_to(atanh((double)0.5L),0.549306144334054845697622618461262852323745279L,1e-14L));
    CHECK(close_to(atanhl((long double)0.5L),0.549306144334054845697622618461262852323745279L,4e-18L));
    CHECK(close_to(atanhf((float)0.875L),1.35402510055110503299800228507435667208654596L,3e-6L));
    CHECK(close_to(atanh((double)0.875L),1.35402510055110503299800228507435667208654596L,1e-14L));
    CHECK(close_to(atanhl((long double)0.875L),1.35402510055110503299800228507435667208654596L,4e-18L));
    CHECK(close_to(cosf((float)-3.5L),-0.936456687290796337698657626671760463019957766L,3e-6L));
    CHECK(close_to(cos((double)-3.5L),-0.936456687290796337698657626671760463019957766L,1e-14L));
    CHECK(close_to(cosl((long double)-3.5L),-0.936456687290796337698657626671760463019957766L,4e-18L));
    CHECK(close_to(cosf((float)-0.25L),0.96891242171064478414459544949418919980413419L,3e-6L));
    CHECK(close_to(cos((double)-0.25L),0.96891242171064478414459544949418919980413419L,1e-14L));
    CHECK(close_to(cosl((long double)-0.25L),0.96891242171064478414459544949418919980413419L,4e-18L));
    CHECK(close_to(cosf((float)0.0L),1.0L,3e-6L));
    CHECK(close_to(cos((double)0.0L),1.0L,1e-14L));
    CHECK(close_to(cosl((long double)0.0L),1.0L,4e-18L));
    CHECK(close_to(cosf((float)0.5L),0.877582561890372716116281582603829651991645197L,3e-6L));
    CHECK(close_to(cos((double)0.5L),0.877582561890372716116281582603829651991645197L,1e-14L));
    CHECK(close_to(cosl((long double)0.5L),0.877582561890372716116281582603829651991645197L,4e-18L));
    CHECK(close_to(cosf((float)8.0L),-0.145500033808613525868841381831194682609319686L,3e-6L));
    CHECK(close_to(cos((double)8.0L),-0.145500033808613525868841381831194682609319686L,1e-14L));
    CHECK(close_to(cosl((long double)8.0L),-0.145500033808613525868841381831194682609319686L,4e-18L));
    CHECK(close_to(sinf((float)-3.5L),0.350783227689619848120368800043635585084981736L,3e-6L));
    CHECK(close_to(sin((double)-3.5L),0.350783227689619848120368800043635585084981736L,1e-14L));
    CHECK(close_to(sinl((long double)-3.5L),0.350783227689619848120368800043635585084981736L,4e-18L));
    CHECK(close_to(sinf((float)-0.25L),-0.24740395925452292959684870484938919589339098L,3e-6L));
    CHECK(close_to(sin((double)-0.25L),-0.24740395925452292959684870484938919589339098L,1e-14L));
    CHECK(close_to(sinl((long double)-0.25L),-0.24740395925452292959684870484938919589339098L,4e-18L));
    CHECK(close_to(sinf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(sin((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(sinl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(sinf((float)0.5L),0.479425538604203000273287935215571388081803368L,3e-6L));
    CHECK(close_to(sin((double)0.5L),0.479425538604203000273287935215571388081803368L,1e-14L));
    CHECK(close_to(sinl((long double)0.5L),0.479425538604203000273287935215571388081803368L,4e-18L));
    CHECK(close_to(sinf((float)8.0L),0.989358246623381777808123598245288672116419081L,3e-6L));
    CHECK(close_to(sin((double)8.0L),0.989358246623381777808123598245288672116419081L,1e-14L));
    CHECK(close_to(sinl((long double)8.0L),0.989358246623381777808123598245288672116419081L,4e-18L));
    CHECK(close_to(tanf((float)-3.5L),-0.374585640158594666330512579989147388450882284L,3e-6L));
    CHECK(close_to(tan((double)-3.5L),-0.374585640158594666330512579989147388450882284L,1e-14L));
    CHECK(close_to(tanl((long double)-3.5L),-0.374585640158594666330512579989147388450882284L,4e-18L));
    CHECK(close_to(tanf((float)-0.25L),-0.255341921221036266504482236490473678204201639L,3e-6L));
    CHECK(close_to(tan((double)-0.25L),-0.255341921221036266504482236490473678204201639L,1e-14L));
    CHECK(close_to(tanl((long double)-0.25L),-0.255341921221036266504482236490473678204201639L,4e-18L));
    CHECK(close_to(tanf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(tan((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(tanl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(tanf((float)0.5L),0.54630248984379051325517946578028538329755172L,3e-6L));
    CHECK(close_to(tan((double)0.5L),0.54630248984379051325517946578028538329755172L,1e-14L));
    CHECK(close_to(tanl((long double)0.5L),0.54630248984379051325517946578028538329755172L,4e-18L));
    CHECK(close_to(tanf((float)8.0L),-6.79971145522037869992526275960863336488141266L,3e-6L));
    CHECK(close_to(tan((double)8.0L),-6.79971145522037869992526275960863336488141266L,1e-14L));
    CHECK(close_to(tanl((long double)8.0L),-6.79971145522037869992526275960863336488141266L,4e-18L));
    CHECK(close_to(coshf((float)-3.5L),16.5728246710573161256965178213761180687716944L,3e-6L));
    CHECK(close_to(cosh((double)-3.5L),16.5728246710573161256965178213761180687716944L,1e-14L));
    CHECK(close_to(coshl((long double)-3.5L),16.5728246710573161256965178213761180687716944L,4e-18L));
    CHECK(close_to(coshf((float)-0.25L),1.03141309987957317615929541752037855281652658L,3e-6L));
    CHECK(close_to(cosh((double)-0.25L),1.03141309987957317615929541752037855281652658L,1e-14L));
    CHECK(close_to(coshl((long double)-0.25L),1.03141309987957317615929541752037855281652658L,4e-18L));
    CHECK(close_to(coshf((float)0.0L),1.0L,3e-6L));
    CHECK(close_to(cosh((double)0.0L),1.0L,1e-14L));
    CHECK(close_to(coshl((long double)0.0L),1.0L,4e-18L));
    CHECK(close_to(coshf((float)0.5L),1.12762596520638078522622516140267201254784712L,3e-6L));
    CHECK(close_to(cosh((double)0.5L),1.12762596520638078522622516140267201254784712L,1e-14L));
    CHECK(close_to(coshl((long double)0.5L),1.12762596520638078522622516140267201254784712L,4e-18L));
    CHECK(close_to(coshf((float)8.0L),1490.47916125217808862771546042100722730849363L,3e-6L));
    CHECK(close_to(cosh((double)8.0L),1490.47916125217808862771546042100722730849363L,1e-14L));
    CHECK(close_to(coshl((long double)8.0L),1490.47916125217808862771546042100722730849363L,4e-18L));
    CHECK(close_to(sinhf((float)-3.5L),-16.5426272876349976249567315290124982237000338L,3e-6L));
    CHECK(close_to(sinh((double)-3.5L),-16.5426272876349976249567315290124982237000338L,1e-14L));
    CHECK(close_to(sinhl((long double)-3.5L),-16.5426272876349976249567315290124982237000338L,4e-18L));
    CHECK(close_to(sinhf((float)-0.25L),-0.252612316808168307914125150542057905519754287L,3e-6L));
    CHECK(close_to(sinh((double)-0.25L),-0.252612316808168307914125150542057905519754287L,1e-14L));
    CHECK(close_to(sinhl((long double)-0.25L),-0.252612316808168307914125150542057905519754287L,4e-18L));
    CHECK(close_to(sinhf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(sinh((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(sinhl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(sinhf((float)0.5L),0.521095305493747361622425626411491559105928983L,3e-6L));
    CHECK(close_to(sinh((double)0.5L),0.521095305493747361622425626411491559105928983L,1e-14L));
    CHECK(close_to(sinhl((long double)0.5L),0.521095305493747361622425626411491559105928983L,4e-18L));
    CHECK(close_to(sinhf((float)8.0L),1490.47882578955018611587663903188144644747431L,3e-6L));
    CHECK(close_to(sinh((double)8.0L),1490.47882578955018611587663903188144644747431L,1e-14L));
    CHECK(close_to(sinhl((long double)8.0L),1490.47882578955018611587663903188144644747431L,4e-18L));
    CHECK(close_to(tanhf((float)-3.5L),-0.998177897611198709284273352450611717351703879L,3e-6L));
    CHECK(close_to(tanh((double)-3.5L),-0.998177897611198709284273352450611717351703879L,1e-14L));
    CHECK(close_to(tanhl((long double)-3.5L),-0.998177897611198709284273352450611717351703879L,4e-18L));
    CHECK(close_to(tanhf((float)-0.25L),-0.244918662403709129277801131491016957506558731L,3e-6L));
    CHECK(close_to(tanh((double)-0.25L),-0.244918662403709129277801131491016957506558731L,1e-14L));
    CHECK(close_to(tanhl((long double)-0.25L),-0.244918662403709129277801131491016957506558731L,4e-18L));
    CHECK(close_to(tanhf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(tanh((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(tanhl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(tanhf((float)0.5L),0.46211715726000975850231848364367254873028928L,3e-6L));
    CHECK(close_to(tanh((double)0.5L),0.46211715726000975850231848364367254873028928L,1e-14L));
    CHECK(close_to(tanhl((long double)0.5L),0.46211715726000975850231848364367254873028928L,4e-18L));
    CHECK(close_to(tanhf((float)8.0L),0.999999774929675889810018832956368393354061888L,3e-6L));
    CHECK(close_to(tanh((double)8.0L),0.999999774929675889810018832956368393354061888L,1e-14L));
    CHECK(close_to(tanhl((long double)8.0L),0.999999774929675889810018832956368393354061888L,4e-18L));
    CHECK(close_to(expf((float)-3.5L),0.0301973834223185007397862923636198450716605322L,3e-6L));
    CHECK(close_to(exp((double)-3.5L),0.0301973834223185007397862923636198450716605322L,1e-14L));
    CHECK(close_to(expl((long double)-3.5L),0.0301973834223185007397862923636198450716605322L,4e-18L));
    CHECK(close_to(expf((float)-0.25L),0.77880078307140486824517026697832064729677229L,3e-6L));
    CHECK(close_to(exp((double)-0.25L),0.77880078307140486824517026697832064729677229L,1e-14L));
    CHECK(close_to(expl((long double)-0.25L),0.77880078307140486824517026697832064729677229L,4e-18L));
    CHECK(close_to(expf((float)0.0L),1.0L,3e-6L));
    CHECK(close_to(exp((double)0.0L),1.0L,1e-14L));
    CHECK(close_to(expl((long double)0.0L),1.0L,4e-18L));
    CHECK(close_to(expf((float)0.5L),1.6487212707001281468486507878141635716537761L,3e-6L));
    CHECK(close_to(exp((double)0.5L),1.6487212707001281468486507878141635716537761L,1e-14L));
    CHECK(close_to(expl((long double)0.5L),1.6487212707001281468486507878141635716537761L,4e-18L));
    CHECK(close_to(expf((float)8.0L),2980.95798704172827474359209945288867375596794L,3e-6L));
    CHECK(close_to(exp((double)8.0L),2980.95798704172827474359209945288867375596794L,1e-14L));
    CHECK(close_to(expl((long double)8.0L),2980.95798704172827474359209945288867375596794L,4e-18L));
    CHECK(close_to(exp2f((float)-3.5L),0.0883883476483184405501055452631061299106044922L,3e-6L));
    CHECK(close_to(exp2((double)-3.5L),0.0883883476483184405501055452631061299106044922L,1e-14L));
    CHECK(close_to(exp2l((long double)-3.5L),0.0883883476483184405501055452631061299106044922L,4e-18L));
    CHECK(close_to(exp2f((float)-0.25L),0.840896415253714543031125476233214895040034262L,3e-6L));
    CHECK(close_to(exp2((double)-0.25L),0.840896415253714543031125476233214895040034262L,1e-14L));
    CHECK(close_to(exp2l((long double)-0.25L),0.840896415253714543031125476233214895040034262L,4e-18L));
    CHECK(close_to(exp2f((float)0.0L),1.0L,3e-6L));
    CHECK(close_to(exp2((double)0.0L),1.0L,1e-14L));
    CHECK(close_to(exp2l((long double)0.0L),1.0L,4e-18L));
    CHECK(close_to(exp2f((float)0.5L),1.41421356237309504880168872420969807856967188L,3e-6L));
    CHECK(close_to(exp2((double)0.5L),1.41421356237309504880168872420969807856967188L,1e-14L));
    CHECK(close_to(exp2l((long double)0.5L),1.41421356237309504880168872420969807856967188L,4e-18L));
    CHECK(close_to(exp2f((float)8.0L),256.0L,3e-6L));
    CHECK(close_to(exp2((double)8.0L),256.0L,1e-14L));
    CHECK(close_to(exp2l((long double)8.0L),256.0L,4e-18L));
    CHECK(close_to(expm1f((float)-3.5L),-0.969802616577681499260213707636380154928339468L,3e-6L));
    CHECK(close_to(expm1((double)-3.5L),-0.969802616577681499260213707636380154928339468L,1e-14L));
    CHECK(close_to(expm1l((long double)-3.5L),-0.969802616577681499260213707636380154928339468L,4e-18L));
    CHECK(close_to(expm1f((float)-0.25L),-0.22119921692859513175482973302167935270322771L,3e-6L));
    CHECK(close_to(expm1((double)-0.25L),-0.22119921692859513175482973302167935270322771L,1e-14L));
    CHECK(close_to(expm1l((long double)-0.25L),-0.22119921692859513175482973302167935270322771L,4e-18L));
    CHECK(close_to(expm1f((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(expm1((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(expm1l((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(expm1f((float)0.5L),0.648721270700128146848650787814163571653776101L,3e-6L));
    CHECK(close_to(expm1((double)0.5L),0.648721270700128146848650787814163571653776101L,1e-14L));
    CHECK(close_to(expm1l((long double)0.5L),0.648721270700128146848650787814163571653776101L,4e-18L));
    CHECK(close_to(expm1f((float)8.0L),2979.95798704172827474359209945288867375596794L,3e-6L));
    CHECK(close_to(expm1((double)8.0L),2979.95798704172827474359209945288867375596794L,1e-14L));
    CHECK(close_to(expm1l((long double)8.0L),2979.95798704172827474359209945288867375596794L,4e-18L));
    CHECK(close_to(logf((float)0.125L),-2.0794415416798359282516963643745297042265004L,3e-6L));
    CHECK(close_to(log((double)0.125L),-2.0794415416798359282516963643745297042265004L,1e-14L));
    CHECK(close_to(logl((long double)0.125L),-2.0794415416798359282516963643745297042265004L,4e-18L));
    CHECK(close_to(logf((float)0.5L),-0.693147180559945309417232121458176568075500134L,3e-6L));
    CHECK(close_to(log((double)0.5L),-0.693147180559945309417232121458176568075500134L,1e-14L));
    CHECK(close_to(logl((long double)0.5L),-0.693147180559945309417232121458176568075500134L,4e-18L));
    CHECK(close_to(logf((float)1.0L),0.0L,3e-6L));
    CHECK(close_to(log((double)1.0L),0.0L,1e-14L));
    CHECK(close_to(logl((long double)1.0L),0.0L,4e-18L));
    CHECK(close_to(logf((float)1.25L),0.223143551314209755766295090309834503374601086L,3e-6L));
    CHECK(close_to(log((double)1.25L),0.223143551314209755766295090309834503374601086L,1e-14L));
    CHECK(close_to(logl((long double)1.25L),0.223143551314209755766295090309834503374601086L,4e-18L));
    CHECK(close_to(logf((float)8.0L),2.0794415416798359282516963643745297042265004L,3e-6L));
    CHECK(close_to(log((double)8.0L),2.0794415416798359282516963643745297042265004L,1e-14L));
    CHECK(close_to(logl((long double)8.0L),2.0794415416798359282516963643745297042265004L,4e-18L));
    CHECK(close_to(log10f((float)0.125L),-0.903089986991943585641216684173479080304569644L,3e-6L));
    CHECK(close_to(log10((double)0.125L),-0.903089986991943585641216684173479080304569644L,1e-14L));
    CHECK(close_to(log10l((long double)0.125L),-0.903089986991943585641216684173479080304569644L,4e-18L));
    CHECK(close_to(log10f((float)0.5L),-0.301029995663981195213738894724493026768189881L,3e-6L));
    CHECK(close_to(log10((double)0.5L),-0.301029995663981195213738894724493026768189881L,1e-14L));
    CHECK(close_to(log10l((long double)0.5L),-0.301029995663981195213738894724493026768189881L,4e-18L));
    CHECK(close_to(log10f((float)1.0L),0.0L,3e-6L));
    CHECK(close_to(log10((double)1.0L),0.0L,1e-14L));
    CHECK(close_to(log10l((long double)1.0L),0.0L,4e-18L));
    CHECK(close_to(log10f((float)1.25L),0.0969100130080564143587833158265209196954303556L,3e-6L));
    CHECK(close_to(log10((double)1.25L),0.0969100130080564143587833158265209196954303556L,1e-14L));
    CHECK(close_to(log10l((long double)1.25L),0.0969100130080564143587833158265209196954303556L,4e-18L));
    CHECK(close_to(log10f((float)8.0L),0.903089986991943585641216684173479080304569644L,3e-6L));
    CHECK(close_to(log10((double)8.0L),0.903089986991943585641216684173479080304569644L,1e-14L));
    CHECK(close_to(log10l((long double)8.0L),0.903089986991943585641216684173479080304569644L,4e-18L));
    CHECK(close_to(log1pf((float)-0.75L),-1.38629436111989061883446424291635313615100027L,3e-6L));
    CHECK(close_to(log1p((double)-0.75L),-1.38629436111989061883446424291635313615100027L,1e-14L));
    CHECK(close_to(log1pl((long double)-0.75L),-1.38629436111989061883446424291635313615100027L,4e-18L));
    CHECK(close_to(log1pf((float)-0.25L),-0.287682072451780927439219005993827431503509711L,3e-6L));
    CHECK(close_to(log1p((double)-0.25L),-0.287682072451780927439219005993827431503509711L,1e-14L));
    CHECK(close_to(log1pl((long double)-0.25L),-0.287682072451780927439219005993827431503509711L,4e-18L));
    CHECK(close_to(log1pf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(log1p((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(log1pl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(log1pf((float)0.5L),0.405465108108164381978013115464349136571990423L,3e-6L));
    CHECK(close_to(log1p((double)0.5L),0.405465108108164381978013115464349136571990423L,1e-14L));
    CHECK(close_to(log1pl((long double)0.5L),0.405465108108164381978013115464349136571990423L,4e-18L));
    CHECK(close_to(log1pf((float)8.0L),2.19722457733621938279049047384505140929498112L,3e-6L));
    CHECK(close_to(log1p((double)8.0L),2.19722457733621938279049047384505140929498112L,1e-14L));
    CHECK(close_to(log1pl((long double)8.0L),2.19722457733621938279049047384505140929498112L,4e-18L));
    CHECK(close_to(log2f((float)0.125L),-3.0L,3e-6L));
    CHECK(close_to(log2((double)0.125L),-3.0L,1e-14L));
    CHECK(close_to(log2l((long double)0.125L),-3.0L,4e-18L));
    CHECK(close_to(log2f((float)0.5L),-1.0L,3e-6L));
    CHECK(close_to(log2((double)0.5L),-1.0L,1e-14L));
    CHECK(close_to(log2l((long double)0.5L),-1.0L,4e-18L));
    CHECK(close_to(log2f((float)1.0L),0.0L,3e-6L));
    CHECK(close_to(log2((double)1.0L),0.0L,1e-14L));
    CHECK(close_to(log2l((long double)1.0L),0.0L,4e-18L));
    CHECK(close_to(log2f((float)1.25L),0.321928094887362347870319429489390175864831393L,3e-6L));
    CHECK(close_to(log2((double)1.25L),0.321928094887362347870319429489390175864831393L,1e-14L));
    CHECK(close_to(log2l((long double)1.25L),0.321928094887362347870319429489390175864831393L,4e-18L));
    CHECK(close_to(log2f((float)8.0L),3.0L,3e-6L));
    CHECK(close_to(log2((double)8.0L),3.0L,1e-14L));
    CHECK(close_to(log2l((long double)8.0L),3.0L,4e-18L));
    CHECK(close_to(cbrtf((float)-3.5L),-1.51829448593783125971040478925283481779072699L,3e-6L));
    CHECK(close_to(cbrt((double)-3.5L),-1.51829448593783125971040478925283481779072699L,1e-14L));
    CHECK(close_to(cbrtl((long double)-3.5L),-1.51829448593783125971040478925283481779072699L,4e-18L));
    CHECK(close_to(cbrtf((float)-0.25L),-0.629960524947436582383605303639114175285125732L,3e-6L));
    CHECK(close_to(cbrt((double)-0.25L),-0.629960524947436582383605303639114175285125732L,1e-14L));
    CHECK(close_to(cbrtl((long double)-0.25L),-0.629960524947436582383605303639114175285125732L,4e-18L));
    CHECK(close_to(cbrtf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(cbrt((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(cbrtl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(cbrtf((float)0.5L),0.793700525984099737375852819636154130195746664L,3e-6L));
    CHECK(close_to(cbrt((double)0.5L),0.793700525984099737375852819636154130195746664L,1e-14L));
    CHECK(close_to(cbrtl((long double)0.5L),0.793700525984099737375852819636154130195746664L,4e-18L));
    CHECK(close_to(cbrtf((float)8.0L),2.0L,3e-6L));
    CHECK(close_to(cbrt((double)8.0L),2.0L,1e-14L));
    CHECK(close_to(cbrtl((long double)8.0L),2.0L,4e-18L));
    CHECK(close_to(fabsf((float)-3.5L),3.5L,3e-6L));
    CHECK(close_to(fabs((double)-3.5L),3.5L,1e-14L));
    CHECK(close_to(fabsl((long double)-3.5L),3.5L,4e-18L));
    CHECK(close_to(fabsf((float)-0.25L),0.25L,3e-6L));
    CHECK(close_to(fabs((double)-0.25L),0.25L,1e-14L));
    CHECK(close_to(fabsl((long double)-0.25L),0.25L,4e-18L));
    CHECK(close_to(fabsf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(fabs((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(fabsl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(fabsf((float)0.5L),0.5L,3e-6L));
    CHECK(close_to(fabs((double)0.5L),0.5L,1e-14L));
    CHECK(close_to(fabsl((long double)0.5L),0.5L,4e-18L));
    CHECK(close_to(fabsf((float)8.0L),8.0L,3e-6L));
    CHECK(close_to(fabs((double)8.0L),8.0L,1e-14L));
    CHECK(close_to(fabsl((long double)8.0L),8.0L,4e-18L));
    CHECK(close_to(sqrtf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(sqrt((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(sqrtl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(sqrtf((float)0.25L),0.5L,3e-6L));
    CHECK(close_to(sqrt((double)0.25L),0.5L,1e-14L));
    CHECK(close_to(sqrtl((long double)0.25L),0.5L,4e-18L));
    CHECK(close_to(sqrtf((float)0.5L),0.707106781186547524400844362104849039284835938L,3e-6L));
    CHECK(close_to(sqrt((double)0.5L),0.707106781186547524400844362104849039284835938L,1e-14L));
    CHECK(close_to(sqrtl((long double)0.5L),0.707106781186547524400844362104849039284835938L,4e-18L));
    CHECK(close_to(sqrtf((float)1.25L),1.11803398874989484820458683436563811772030918L,3e-6L));
    CHECK(close_to(sqrt((double)1.25L),1.11803398874989484820458683436563811772030918L,1e-14L));
    CHECK(close_to(sqrtl((long double)1.25L),1.11803398874989484820458683436563811772030918L,4e-18L));
    CHECK(close_to(sqrtf((float)8.0L),2.82842712474619009760337744841939615713934375L,3e-6L));
    CHECK(close_to(sqrt((double)8.0L),2.82842712474619009760337744841939615713934375L,1e-14L));
    CHECK(close_to(sqrtl((long double)8.0L),2.82842712474619009760337744841939615713934375L,4e-18L));
    CHECK(close_to(erff((float)-3.5L),-0.99999925690162765858725447631624390436427934L,3e-6L));
    CHECK(close_to(erf((double)-3.5L),-0.99999925690162765858725447631624390436427934L,1e-14L));
    CHECK(close_to(erfl((long double)-3.5L),-0.99999925690162765858725447631624390436427934L,4e-18L));
    CHECK(close_to(erff((float)-0.25L),-0.276326390168236932985068267764815712065353978L,3e-6L));
    CHECK(close_to(erf((double)-0.25L),-0.276326390168236932985068267764815712065353978L,1e-14L));
    CHECK(close_to(erfl((long double)-0.25L),-0.276326390168236932985068267764815712065353978L,4e-18L));
    CHECK(close_to(erff((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(erf((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(erfl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(erff((float)0.5L),0.520499877813046537682746653891964528736451576L,3e-6L));
    CHECK(close_to(erf((double)0.5L),0.520499877813046537682746653891964528736451576L,1e-14L));
    CHECK(close_to(erfl((long double)0.5L),0.520499877813046537682746653891964528736451576L,4e-18L));
    CHECK(close_to(erff((float)8.0L),0.999999999999999999999999999988775702827017073L,3e-6L));
    CHECK(close_to(erf((double)8.0L),0.999999999999999999999999999988775702827017073L,1e-14L));
    CHECK(close_to(erfl((long double)8.0L),0.999999999999999999999999999988775702827017073L,4e-18L));
    CHECK(close_to(erfcf((float)-3.5L),1.99999925690162765858725447631624390436427934L,3e-6L));
    CHECK(close_to(erfc((double)-3.5L),1.99999925690162765858725447631624390436427934L,1e-14L));
    CHECK(close_to(erfcl((long double)-3.5L),1.99999925690162765858725447631624390436427934L,4e-18L));
    CHECK(close_to(erfcf((float)-0.25L),1.27632639016823693298506826776481571206535398L,3e-6L));
    CHECK(close_to(erfc((double)-0.25L),1.27632639016823693298506826776481571206535398L,1e-14L));
    CHECK(close_to(erfcl((long double)-0.25L),1.27632639016823693298506826776481571206535398L,4e-18L));
    CHECK(close_to(erfcf((float)0.0L),1.0L,3e-6L));
    CHECK(close_to(erfc((double)0.0L),1.0L,1e-14L));
    CHECK(close_to(erfcl((long double)0.0L),1.0L,4e-18L));
    CHECK(close_to(erfcf((float)0.5L),0.479500122186953462317253346108035471263548424L,3e-6L));
    CHECK(close_to(erfc((double)0.5L),0.479500122186953462317253346108035471263548424L,1e-14L));
    CHECK(close_to(erfcl((long double)0.5L),0.479500122186953462317253346108035471263548424L,4e-18L));
    CHECK(close_to(erfcf((float)8.0L),1.12242971729829270799678884431702790934319292e-29L,3e-6L));
    CHECK(close_to(erfc((double)8.0L),1.12242971729829270799678884431702790934319292e-29L,1e-14L));
    CHECK(close_to(erfcl((long double)8.0L),1.12242971729829270799678884431702790934319292e-29L,4e-18L));
    CHECK(close_to(lgammaf((float)0.125L),2.01941835755379634532029052116709958994828095L,3e-6L));
    CHECK(close_to(lgamma((double)0.125L),2.01941835755379634532029052116709958994828095L,1e-14L));
    CHECK(close_to(lgammal((long double)0.125L),2.01941835755379634532029052116709958994828095L,4e-18L));
    CHECK(close_to(lgammaf((float)0.5L),0.572364942924700087071713675676529355823647406L,3e-6L));
    CHECK(close_to(lgamma((double)0.5L),0.572364942924700087071713675676529355823647406L,1e-14L));
    CHECK(close_to(lgammal((long double)0.5L),0.572364942924700087071713675676529355823647406L,4e-18L));
    CHECK(close_to(lgammaf((float)1.0L),0.0L,3e-6L));
    CHECK(close_to(lgamma((double)1.0L),0.0L,1e-14L));
    CHECK(close_to(lgammal((long double)1.0L),0.0L,4e-18L));
    CHECK(close_to(lgammaf((float)1.25L),-0.0982718364218131614638538026966358402256227036L,3e-6L));
    CHECK(close_to(lgamma((double)1.25L),-0.0982718364218131614638538026966358402256227036L,1e-14L));
    CHECK(close_to(lgammal((long double)1.25L),-0.0982718364218131614638538026966358402256227036L,4e-18L));
    CHECK(close_to(lgammaf((float)8.0L),8.52516136106541430016553103634712505075966774L,3e-6L));
    CHECK(close_to(lgamma((double)8.0L),8.52516136106541430016553103634712505075966774L,1e-14L));
    CHECK(close_to(lgammal((long double)8.0L),8.52516136106541430016553103634712505075966774L,4e-18L));
    CHECK(close_to(tgammaf((float)0.125L),7.53394159879761190469922984121513362461041959L,3e-6L));
    CHECK(close_to(tgamma((double)0.125L),7.53394159879761190469922984121513362461041959L,1e-14L));
    CHECK(close_to(tgammal((long double)0.125L),7.53394159879761190469922984121513362461041959L,4e-18L));
    CHECK(close_to(tgammaf((float)0.5L),1.77245385090551602729816748334114518279754946L,3e-6L));
    CHECK(close_to(tgamma((double)0.5L),1.77245385090551602729816748334114518279754946L,1e-14L));
    CHECK(close_to(tgammal((long double)0.5L),1.77245385090551602729816748334114518279754946L,4e-18L));
    CHECK(close_to(tgammaf((float)1.0L),1.0L,3e-6L));
    CHECK(close_to(tgamma((double)1.0L),1.0L,1e-14L));
    CHECK(close_to(tgammal((long double)1.0L),1.0L,4e-18L));
    CHECK(close_to(tgammaf((float)1.25L),0.906402477055477077982671288966918000748791921L,3e-6L));
    CHECK(close_to(tgamma((double)1.25L),0.906402477055477077982671288966918000748791921L,1e-14L));
    CHECK(close_to(tgammal((long double)1.25L),0.906402477055477077982671288966918000748791921L,4e-18L));
    CHECK(close_to(tgammaf((float)8.0L),5040.0L,3e-6L));
    CHECK(close_to(tgamma((double)8.0L),5040.0L,1e-14L));
    CHECK(close_to(tgammal((long double)8.0L),5040.0L,4e-18L));
    CHECK(close_to(ceilf((float)-3.5L),-3.0L,3e-6L));
    CHECK(close_to(ceil((double)-3.5L),-3.0L,1e-14L));
    CHECK(close_to(ceill((long double)-3.5L),-3.0L,4e-18L));
    CHECK(close_to(ceilf((float)-0.25L),0.0L,3e-6L));
    CHECK(close_to(ceil((double)-0.25L),0.0L,1e-14L));
    CHECK(close_to(ceill((long double)-0.25L),0.0L,4e-18L));
    CHECK(close_to(ceilf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(ceil((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(ceill((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(ceilf((float)0.5L),1.0L,3e-6L));
    CHECK(close_to(ceil((double)0.5L),1.0L,1e-14L));
    CHECK(close_to(ceill((long double)0.5L),1.0L,4e-18L));
    CHECK(close_to(ceilf((float)8.0L),8.0L,3e-6L));
    CHECK(close_to(ceil((double)8.0L),8.0L,1e-14L));
    CHECK(close_to(ceill((long double)8.0L),8.0L,4e-18L));
    CHECK(close_to(floorf((float)-3.5L),-4.0L,3e-6L));
    CHECK(close_to(floor((double)-3.5L),-4.0L,1e-14L));
    CHECK(close_to(floorl((long double)-3.5L),-4.0L,4e-18L));
    CHECK(close_to(floorf((float)-0.25L),-1.0L,3e-6L));
    CHECK(close_to(floor((double)-0.25L),-1.0L,1e-14L));
    CHECK(close_to(floorl((long double)-0.25L),-1.0L,4e-18L));
    CHECK(close_to(floorf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(floor((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(floorl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(floorf((float)0.5L),0.0L,3e-6L));
    CHECK(close_to(floor((double)0.5L),0.0L,1e-14L));
    CHECK(close_to(floorl((long double)0.5L),0.0L,4e-18L));
    CHECK(close_to(floorf((float)8.0L),8.0L,3e-6L));
    CHECK(close_to(floor((double)8.0L),8.0L,1e-14L));
    CHECK(close_to(floorl((long double)8.0L),8.0L,4e-18L));
    CHECK(close_to(truncf((float)-3.5L),-3.0L,3e-6L));
    CHECK(close_to(trunc((double)-3.5L),-3.0L,1e-14L));
    CHECK(close_to(truncl((long double)-3.5L),-3.0L,4e-18L));
    CHECK(close_to(truncf((float)-0.25L),0.0L,3e-6L));
    CHECK(close_to(trunc((double)-0.25L),0.0L,1e-14L));
    CHECK(close_to(truncl((long double)-0.25L),0.0L,4e-18L));
    CHECK(close_to(truncf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(trunc((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(truncl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(truncf((float)0.5L),0.0L,3e-6L));
    CHECK(close_to(trunc((double)0.5L),0.0L,1e-14L));
    CHECK(close_to(truncl((long double)0.5L),0.0L,4e-18L));
    CHECK(close_to(truncf((float)8.0L),8.0L,3e-6L));
    CHECK(close_to(trunc((double)8.0L),8.0L,1e-14L));
    CHECK(close_to(truncl((long double)8.0L),8.0L,4e-18L));
    CHECK(close_to(roundf((float)-3.5L),-4.0L,3e-6L));
    CHECK(close_to(round((double)-3.5L),-4.0L,1e-14L));
    CHECK(close_to(roundl((long double)-3.5L),-4.0L,4e-18L));
    CHECK(close_to(roundf((float)-0.25L),0.0L,3e-6L));
    CHECK(close_to(round((double)-0.25L),0.0L,1e-14L));
    CHECK(close_to(roundl((long double)-0.25L),0.0L,4e-18L));
    CHECK(close_to(roundf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(round((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(roundl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(roundf((float)0.5L),1.0L,3e-6L));
    CHECK(close_to(round((double)0.5L),1.0L,1e-14L));
    CHECK(close_to(roundl((long double)0.5L),1.0L,4e-18L));
    CHECK(close_to(roundf((float)8.0L),8.0L,3e-6L));
    CHECK(close_to(round((double)8.0L),8.0L,1e-14L));
    CHECK(close_to(roundl((long double)8.0L),8.0L,4e-18L));
    CHECK(close_to(nearbyintf((float)-3.5L),-4.0L,3e-6L));
    CHECK(close_to(nearbyint((double)-3.5L),-4.0L,1e-14L));
    CHECK(close_to(nearbyintl((long double)-3.5L),-4.0L,4e-18L));
    CHECK(close_to(nearbyintf((float)-0.25L),0.0L,3e-6L));
    CHECK(close_to(nearbyint((double)-0.25L),0.0L,1e-14L));
    CHECK(close_to(nearbyintl((long double)-0.25L),0.0L,4e-18L));
    CHECK(close_to(nearbyintf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(nearbyint((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(nearbyintl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(nearbyintf((float)0.5L),0.0L,3e-6L));
    CHECK(close_to(nearbyint((double)0.5L),0.0L,1e-14L));
    CHECK(close_to(nearbyintl((long double)0.5L),0.0L,4e-18L));
    CHECK(close_to(nearbyintf((float)8.0L),8.0L,3e-6L));
    CHECK(close_to(nearbyint((double)8.0L),8.0L,1e-14L));
    CHECK(close_to(nearbyintl((long double)8.0L),8.0L,4e-18L));
    CHECK(close_to(rintf((float)-3.5L),-4.0L,3e-6L));
    CHECK(close_to(rint((double)-3.5L),-4.0L,1e-14L));
    CHECK(close_to(rintl((long double)-3.5L),-4.0L,4e-18L));
    CHECK(close_to(rintf((float)-0.25L),0.0L,3e-6L));
    CHECK(close_to(rint((double)-0.25L),0.0L,1e-14L));
    CHECK(close_to(rintl((long double)-0.25L),0.0L,4e-18L));
    CHECK(close_to(rintf((float)0.0L),0.0L,3e-6L));
    CHECK(close_to(rint((double)0.0L),0.0L,1e-14L));
    CHECK(close_to(rintl((long double)0.0L),0.0L,4e-18L));
    CHECK(close_to(rintf((float)0.5L),0.0L,3e-6L));
    CHECK(close_to(rint((double)0.5L),0.0L,1e-14L));
    CHECK(close_to(rintl((long double)0.5L),0.0L,4e-18L));
    CHECK(close_to(rintf((float)8.0L),8.0L,3e-6L));
    CHECK(close_to(rint((double)8.0L),8.0L,1e-14L));
    CHECK(close_to(rintl((long double)8.0L),8.0L,4e-18L));
    CHECK(close_to(logbf((float)-3.5L),1.0L,3e-6L));
    CHECK(close_to(logb((double)-3.5L),1.0L,1e-14L));
    CHECK(close_to(logbl((long double)-3.5L),1.0L,4e-18L));
    CHECK(close_to(logbf((float)-0.25L),-2.0L,3e-6L));
    CHECK(close_to(logb((double)-0.25L),-2.0L,1e-14L));
    CHECK(close_to(logbl((long double)-0.25L),-2.0L,4e-18L));
    CHECK(close_to(logbf((float)0.5L),-1.0L,3e-6L));
    CHECK(close_to(logb((double)0.5L),-1.0L,1e-14L));
    CHECK(close_to(logbl((long double)0.5L),-1.0L,4e-18L));
    CHECK(close_to(logbf((float)8.0L),3.0L,3e-6L));
    CHECK(close_to(logb((double)8.0L),3.0L,1e-14L));
    CHECK(close_to(logbl((long double)8.0L),3.0L,4e-18L));
    CHECK(close_to(atan2f((float)1.25L,(float)0.5L),1.19028994968253173292773377482931833760117899L,3e-6L));
    CHECK(close_to(atan2((double)1.25L,(double)0.5L),1.19028994968253173292773377482931833760117899L,1e-14L));
    CHECK(close_to(atan2l((long double)1.25L,(long double)0.5L),1.19028994968253173292773377482931833760117899L,4e-18L));
    CHECK(close_to(atan2f((float)3.5L,(float)2.25L),0.999458846961269816483341300168905809127437579L,3e-6L));
    CHECK(close_to(atan2((double)3.5L,(double)2.25L),0.999458846961269816483341300168905809127437579L,1e-14L));
    CHECK(close_to(atan2l((long double)3.5L,(long double)2.25L),0.999458846961269816483341300168905809127437579L,4e-18L));
    CHECK(close_to(hypotf((float)1.25L,(float)0.5L),1.34629120178362600781267762288508238907378004L,3e-6L));
    CHECK(close_to(hypot((double)1.25L,(double)0.5L),1.34629120178362600781267762288508238907378004L,1e-14L));
    CHECK(close_to(hypotl((long double)1.25L,(long double)0.5L),1.34629120178362600781267762288508238907378004L,4e-18L));
    CHECK(close_to(hypotf((float)3.5L,(float)2.25L),4.16082924427330951723205369633649663701731158L,3e-6L));
    CHECK(close_to(hypot((double)3.5L,(double)2.25L),4.16082924427330951723205369633649663701731158L,1e-14L));
    CHECK(close_to(hypotl((long double)3.5L,(long double)2.25L),4.16082924427330951723205369633649663701731158L,4e-18L));
    CHECK(close_to(powf((float)1.25L,(float)0.5L),1.11803398874989484820458683436563811772030918L,3e-6L));
    CHECK(close_to(pow((double)1.25L,(double)0.5L),1.11803398874989484820458683436563811772030918L,1e-14L));
    CHECK(close_to(powl((long double)1.25L,(long double)0.5L),1.11803398874989484820458683436563811772030918L,4e-18L));
    CHECK(close_to(powf((float)3.5L,(float)2.25L),16.7553343983754108060189284262337975777677917L,3e-6L));
    CHECK(close_to(pow((double)3.5L,(double)2.25L),16.7553343983754108060189284262337975777677917L,1e-14L));
    CHECK(close_to(powl((long double)3.5L,(long double)2.25L),16.7553343983754108060189284262337975777677917L,4e-18L));
    CHECK(close_to(fmodf((float)1.25L,(float)0.5L),0.25L,3e-6L));
    CHECK(close_to(fmod((double)1.25L,(double)0.5L),0.25L,1e-14L));
    CHECK(close_to(fmodl((long double)1.25L,(long double)0.5L),0.25L,4e-18L));
    CHECK(close_to(fmodf((float)3.5L,(float)2.25L),1.25L,3e-6L));
    CHECK(close_to(fmod((double)3.5L,(double)2.25L),1.25L,1e-14L));
    CHECK(close_to(fmodl((long double)3.5L,(long double)2.25L),1.25L,4e-18L));
    CHECK(close_to(remainderf((float)1.25L,(float)0.5L),0.25L,3e-6L));
    CHECK(close_to(remainder((double)1.25L,(double)0.5L),0.25L,1e-14L));
    CHECK(close_to(remainderl((long double)1.25L,(long double)0.5L),0.25L,4e-18L));
    CHECK(close_to(remainderf((float)3.5L,(float)2.25L),-1.0L,3e-6L));
    CHECK(close_to(remainder((double)3.5L,(double)2.25L),-1.0L,1e-14L));
    CHECK(close_to(remainderl((long double)3.5L,(long double)2.25L),-1.0L,4e-18L));
    CHECK(close_to(copysignf((float)1.25L,(float)0.5L),1.25L,3e-6L));
    CHECK(close_to(copysign((double)1.25L,(double)0.5L),1.25L,1e-14L));
    CHECK(close_to(copysignl((long double)1.25L,(long double)0.5L),1.25L,4e-18L));
    CHECK(close_to(copysignf((float)3.5L,(float)2.25L),3.5L,3e-6L));
    CHECK(close_to(copysign((double)3.5L,(double)2.25L),3.5L,1e-14L));
    CHECK(close_to(copysignl((long double)3.5L,(long double)2.25L),3.5L,4e-18L));
    CHECK(close_to(fdimf((float)1.25L,(float)0.5L),0.75L,3e-6L));
    CHECK(close_to(fdim((double)1.25L,(double)0.5L),0.75L,1e-14L));
    CHECK(close_to(fdiml((long double)1.25L,(long double)0.5L),0.75L,4e-18L));
    CHECK(close_to(fdimf((float)3.5L,(float)2.25L),1.25L,3e-6L));
    CHECK(close_to(fdim((double)3.5L,(double)2.25L),1.25L,1e-14L));
    CHECK(close_to(fdiml((long double)3.5L,(long double)2.25L),1.25L,4e-18L));
    CHECK(close_to(fmaxf((float)1.25L,(float)0.5L),1.25L,3e-6L));
    CHECK(close_to(fmax((double)1.25L,(double)0.5L),1.25L,1e-14L));
    CHECK(close_to(fmaxl((long double)1.25L,(long double)0.5L),1.25L,4e-18L));
    CHECK(close_to(fmaxf((float)3.5L,(float)2.25L),3.5L,3e-6L));
    CHECK(close_to(fmax((double)3.5L,(double)2.25L),3.5L,1e-14L));
    CHECK(close_to(fmaxl((long double)3.5L,(long double)2.25L),3.5L,4e-18L));
    CHECK(close_to(fminf((float)1.25L,(float)0.5L),0.5L,3e-6L));
    CHECK(close_to(fmin((double)1.25L,(double)0.5L),0.5L,1e-14L));
    CHECK(close_to(fminl((long double)1.25L,(long double)0.5L),0.5L,4e-18L));
    CHECK(close_to(fminf((float)3.5L,(float)2.25L),2.25L,3e-6L));
    CHECK(close_to(fmin((double)3.5L,(double)2.25L),2.25L,1e-14L));
    CHECK(close_to(fminl((long double)3.5L,(long double)2.25L),2.25L,4e-18L));
    CHECK(lrintf((float)-3.5)==-4);
    CHECK(llrintf((float)-3.5)==-4);
    CHECK(lroundf((float)-3.5)==-4);
    CHECK(llroundf((float)-3.5)==-4);
    CHECK(ilogbf((float)8)==3);
    CHECK(ldexpf((float)1.25,5)==40);
    CHECK(scalbnf((float)1.25,5)==40);
    CHECK(scalblnf((float)1.25,5)==40);
    CHECK(nextafterf((float)1,(float)2)==(float)1+FLT_EPSILON);
    CHECK(nexttowardf((float)1,2.0L)==(float)1+FLT_EPSILON);
    CHECK(isnan(nanf("payload")));
    CHECK(fmaf((float)1.25,(float)2.5,(float)-0.25)==(float)2.875);
    {
        float integral; int exponent;
        CHECK(frexpf((float)1.25,&exponent)==(float)0.625 && exponent==1);
        CHECK(modff((float)-3.5,&integral)==(float)-0.5 && integral==(float)-3);
        int quotient; CHECK(remquof((float)7,(float)2,&quotient)==(float)-1 && (quotient&7)==4);
    }
    CHECK(lrint((double)-3.5)==-4);
    CHECK(llrint((double)-3.5)==-4);
    CHECK(lround((double)-3.5)==-4);
    CHECK(llround((double)-3.5)==-4);
    CHECK(ilogb((double)8)==3);
    CHECK(ldexp((double)1.25,5)==40);
    CHECK(scalbn((double)1.25,5)==40);
    CHECK(scalbln((double)1.25,5)==40);
    CHECK(nextafter((double)1,(double)2)==(double)1+DBL_EPSILON);
    CHECK(nexttoward((double)1,2.0L)==(double)1+DBL_EPSILON);
    CHECK(isnan(nan("payload")));
    CHECK(fma((double)1.25,(double)2.5,(double)-0.25)==(double)2.875);
    {
        double integral; int exponent;
        CHECK(frexp((double)1.25,&exponent)==(double)0.625 && exponent==1);
        CHECK(modf((double)-3.5,&integral)==(double)-0.5 && integral==(double)-3);
        int quotient; CHECK(remquo((double)7,(double)2,&quotient)==(double)-1 && (quotient&7)==4);
    }
    CHECK(lrintl((long double)-3.5)==-4);
    CHECK(llrintl((long double)-3.5)==-4);
    CHECK(lroundl((long double)-3.5)==-4);
    CHECK(llroundl((long double)-3.5)==-4);
    CHECK(ilogbl((long double)8)==3);
    CHECK(ldexpl((long double)1.25,5)==40);
    CHECK(scalbnl((long double)1.25,5)==40);
    CHECK(scalblnl((long double)1.25,5)==40);
    CHECK(nextafterl((long double)1,(long double)2)==(long double)1+LDBL_EPSILON);
    CHECK(nexttowardl((long double)1,2.0L)==(long double)1+LDBL_EPSILON);
    CHECK(isnan(nanl("payload")));
    CHECK(fmal((long double)1.25,(long double)2.5,(long double)-0.25)==(long double)2.875);
    {
        long double integral; int exponent;
        CHECK(frexpl((long double)1.25,&exponent)==(long double)0.625 && exponent==1);
        CHECK(modfl((long double)-3.5,&integral)==(long double)-0.5 && integral==(long double)-3);
        int quotient; CHECK(remquol((long double)7,(long double)2,&quotient)==(long double)-1 && (quotient&7)==4);
    }
    {
        float complex value=cacosf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),0.509610554326153960756554647045619295532750397L,3e-6L) && close_to(cimagf(value),-0.898893629369482514385106726227248524198415448L,3e-6L));
    }
    {
        double complex value=cacos(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),0.509610554326153960756554647045619295532750397L,1e-14L) && close_to(cimag(value),-0.898893629369482514385106726227248524198415448L,1e-14L));
    }
    {
        long double complex value=cacosl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),0.509610554326153960756554647045619295532750397L,4e-18L) && close_to(cimagl(value),-0.898893629369482514385106726227248524198415448L,4e-18L));
    }
    {
        float complex value=cacosf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),1.70899149792816044435227043127941513079441531L,3e-6L) && close_to(cimagf(value),-1.20274555164396792617178584992166021603985509L,3e-6L));
    }
    {
        double complex value=cacos(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),1.70899149792816044435227043127941513079441531L,1e-14L) && close_to(cimag(value),-1.20274555164396792617178584992166021603985509L,1e-14L));
    }
    {
        long double complex value=cacosl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),1.70899149792816044435227043127941513079441531L,4e-18L) && close_to(cimagl(value),-1.20274555164396792617178584992166021603985509L,4e-18L));
    }
    {
        float complex value=casinf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),1.0611857724687426584747670445941321465658343L,3e-6L) && close_to(cimagf(value),0.898893629369482514385106726227248524198415448L,3e-6L));
    }
    {
        double complex value=casin(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),1.0611857724687426584747670445941321465658343L,1e-14L) && close_to(cimag(value),0.898893629369482514385106726227248524198415448L,1e-14L));
    }
    {
        long double complex value=casinl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),1.0611857724687426584747670445941321465658343L,4e-18L) && close_to(cimagl(value),0.898893629369482514385106726227248524198415448L,4e-18L));
    }
    {
        float complex value=casinf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),-0.138195171133263825120948739639663688695830607L,3e-6L) && close_to(cimagf(value),1.20274555164396792617178584992166021603985509L,3e-6L));
    }
    {
        double complex value=casin(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),-0.138195171133263825120948739639663688695830607L,1e-14L) && close_to(cimag(value),1.20274555164396792617178584992166021603985509L,1e-14L));
    }
    {
        long double complex value=casinl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),-0.138195171133263825120948739639663688695830607L,4e-18L) && close_to(cimagl(value),1.20274555164396792617178584992166021603985509L,4e-18L));
    }
    {
        float complex value=catanf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),0.94251411293961746452250397267036422031220922L,3e-6L) && close_to(cimagf(value),0.185894508546709305392029267765925785205292207L,3e-6L));
    }
    {
        double complex value=catan(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),0.94251411293961746452250397267036422031220922L,1e-14L) && close_to(cimag(value),0.185894508546709305392029267765925785205292207L,1e-14L));
    }
    {
        long double complex value=catanl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),0.94251411293961746452250397267036422031220922L,4e-18L) && close_to(cimagl(value),0.185894508546709305392029267765925785205292207L,4e-18L));
    }
    {
        float complex value=catanf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),-1.38880684854007457481341663584815453620595533L,3e-6L) && close_to(cimagf(value),0.751420651101789769070859733421700379341320308L,3e-6L));
    }
    {
        double complex value=catan(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),-1.38880684854007457481341663584815453620595533L,1e-14L) && close_to(cimag(value),0.751420651101789769070859733421700379341320308L,1e-14L));
    }
    {
        long double complex value=catanl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),-1.38880684854007457481341663584815453620595533L,4e-18L) && close_to(cimagl(value),0.751420651101789769070859733421700379341320308L,4e-18L));
    }
    {
        float complex value=ccosf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),0.355565683247121017060066696855352590452798047L,3e-6L) && close_to(cimagf(value),-0.49451143013196675384680477432577774682646394L,3e-6L));
    }
    {
        double complex value=ccos(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),0.355565683247121017060066696855352590452798047L,1e-14L) && close_to(cimag(value),-0.49451143013196675384680477432577774682646394L,1e-14L));
    }
    {
        long double complex value=ccosl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),0.355565683247121017060066696855352590452798047L,4e-18L) && close_to(cimagl(value),-0.49451143013196675384680477432577774682646394L,4e-18L));
    }
    {
        float complex value=ccosf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),2.27927889716074089355553518090949983928482179L,3e-6L) && close_to(cimagf(value),0.526792167549771013940412040573829016028438092L,3e-6L));
    }
    {
        double complex value=ccos(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),2.27927889716074089355553518090949983928482179L,1e-14L) && close_to(cimag(value),0.526792167549771013940412040573829016028438092L,1e-14L));
    }
    {
        long double complex value=ccosl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),2.27927889716074089355553518090949983928482179L,4e-18L) && close_to(cimagl(value),0.526792167549771013940412040573829016028438092L,4e-18L));
    }
    {
        float complex value=csinf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),1.0700996973668527740056301134174829844648861L,3e-6L) && close_to(cimagf(value),0.164313002761372640271542324868098405629582893L,3e-6L));
    }
    {
        double complex value=csin(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),1.0700996973668527740056301134174829844648861L,1e-14L) && close_to(cimag(value),0.164313002761372640271542324868098405629582893L,1e-14L));
    }
    {
        long double complex value=csinl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),1.0700996973668527740056301134174829844648861L,4e-18L) && close_to(cimagl(value),0.164313002761372640271542324868098405629582893L,4e-18L));
    }
    {
        float complex value=csinf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),-0.581995452599588323294590757806724097873227199L,3e-6L) && close_to(cimagf(value),2.06308531333464174416034462298570006394383239L,3e-6L));
    }
    {
        double complex value=csin(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),-0.581995452599588323294590757806724097873227199L,1e-14L) && close_to(cimag(value),2.06308531333464174416034462298570006394383239L,1e-14L));
    }
    {
        long double complex value=csinl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),-0.581995452599588323294590757806724097873227199L,4e-18L) && close_to(cimagl(value),2.06308531333464174416034462298570006394383239L,4e-18L));
    }
    {
        float complex value=ctanf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),0.806634698851073620125348440934407966249934789L,3e-6L) && close_to(cimagf(value),1.58396354828442398617095276028698438796442074L,3e-6L));
    }
    {
        double complex value=ctan(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),0.806634698851073620125348440934407966249934789L,1e-14L) && close_to(cimag(value),1.58396354828442398617095276028698438796442074L,1e-14L));
    }
    {
        long double complex value=ctanl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),0.806634698851073620125348440934407966249934789L,4e-18L) && close_to(cimagl(value),1.58396354828442398617095276028698438796442074L,4e-18L));
    }
    {
        float complex value=ctanf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),-0.0438021769251671803409819577336099944233093752L,3e-6L) && close_to(cimagf(value),0.915271913261314024251455560857442457395368077L,3e-6L));
    }
    {
        double complex value=ctan(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),-0.0438021769251671803409819577336099944233093752L,1e-14L) && close_to(cimag(value),0.915271913261314024251455560857442457395368077L,1e-14L));
    }
    {
        long double complex value=ctanl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),-0.0438021769251671803409819577336099944233093752L,4e-18L) && close_to(cimagl(value),0.915271913261314024251455560857442457395368077L,4e-18L));
    }
    {
        float complex value=cacoshf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),0.898893629369482514385106726227248524198415448L,3e-6L) && close_to(cimagf(value),0.509610554326153960756554647045619295532750397L,3e-6L));
    }
    {
        double complex value=cacosh(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),0.898893629369482514385106726227248524198415448L,1e-14L) && close_to(cimag(value),0.509610554326153960756554647045619295532750397L,1e-14L));
    }
    {
        long double complex value=cacoshl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),0.898893629369482514385106726227248524198415448L,4e-18L) && close_to(cimagl(value),0.509610554326153960756554647045619295532750397L,4e-18L));
    }
    {
        float complex value=cacoshf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),1.20274555164396792617178584992166021603985509L,3e-6L) && close_to(cimagf(value),1.70899149792816044435227043127941513079441531L,3e-6L));
    }
    {
        double complex value=cacosh(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),1.20274555164396792617178584992166021603985509L,1e-14L) && close_to(cimag(value),1.70899149792816044435227043127941513079441531L,1e-14L));
    }
    {
        long double complex value=cacoshl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),1.20274555164396792617178584992166021603985509L,4e-18L) && close_to(cimagl(value),1.70899149792816044435227043127941513079441531L,4e-18L));
    }
    {
        float complex value=casinhf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),1.08557655772077853483582994757871357744460046L,3e-6L) && close_to(cimagf(value),0.307981371572118604862299563359984883834654131L,3e-6L));
    }
    {
        double complex value=casinh(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),1.08557655772077853483582994757871357744460046L,1e-14L) && close_to(cimag(value),0.307981371572118604862299563359984883834654131L,1e-14L));
    }
    {
        long double complex value=casinhl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),1.08557655772077853483582994757871357744460046L,4e-18L) && close_to(cimagl(value),0.307981371572118604862299563359984883834654131L,4e-18L));
    }
    {
        float complex value=casinhf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),-0.993730466037242809685551624001451078100818338L,3e-6L) && close_to(cimagf(value),1.35462561054635846234850365877096643119495435L,3e-6L));
    }
    {
        double complex value=casinh(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),-0.993730466037242809685551624001451078100818338L,1e-14L) && close_to(cimag(value),1.35462561054635846234850365877096643119495435L,1e-14L));
    }
    {
        long double complex value=casinhl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),-0.993730466037242809685551624001451078100818338L,4e-18L) && close_to(cimagl(value),1.35462561054635846234850365877096643119495435L,4e-18L));
    }
    {
        float complex value=catanhf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),0.708303336014054020062383654468281633897050753L,3e-6L) && close_to(cimagf(value),1.12655644083482234874387583667545221762075735L,3e-6L));
    }
    {
        double complex value=catanh(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),0.708303336014054020062383654468281633897050753L,1e-14L) && close_to(cimag(value),1.12655644083482234874387583667545221762075735L,1e-14L));
    }
    {
        long double complex value=catanhl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),0.708303336014054020062383654468281633897050753L,4e-18L) && close_to(cimagl(value),1.12655644083482234874387583667545221762075735L,4e-18L));
    }
    {
        float complex value=catanhf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),-0.0760528436007478728400348240885939243737748183L,3e-6L) && close_to(cimagf(value),0.991603384196141963065556490653439189572696446L,3e-6L));
    }
    {
        double complex value=catanh(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),-0.0760528436007478728400348240885939243737748183L,1e-14L) && close_to(cimag(value),0.991603384196141963065556490653439189572696446L,1e-14L));
    }
    {
        long double complex value=catanhl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),-0.0760528436007478728400348240885939243737748183L,4e-18L) && close_to(cimagl(value),0.991603384196141963065556490653439189572696446L,4e-18L));
    }
    {
        float complex value=ccoshf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),1.65724786405391469760187723912637704143901099L,3e-6L) && close_to(cimagf(value),0.768000917873572847808542519760838895498981644L,3e-6L));
    }
    {
        double complex value=ccosh(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),1.65724786405391469760187723912637704143901099L,1e-14L) && close_to(cimag(value),0.768000917873572847808542519760838895498981644L,1e-14L));
    }
    {
        long double complex value=ccoshl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),1.65724786405391469760187723912637704143901099L,4e-18L) && close_to(cimagl(value),0.768000917873572847808542519760838895498981644L,4e-18L));
    }
    {
        float complex value=ccoshf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),0.072959276448891971848860315292760224881932815L,3e-6L) && close_to(cimagf(value),-0.251979519570583000266872405399778959289131696L,3e-6L));
    }
    {
        double complex value=ccosh(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),0.072959276448891971848860315292760224881932815L,1e-14L) && close_to(cimag(value),-0.251979519570583000266872405399778959289131696L,1e-14L));
    }
    {
        long double complex value=ccoshl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),0.072959276448891971848860315292760224881932815L,4e-18L) && close_to(cimagl(value),-0.251979519570583000266872405399778959289131696L,4e-18L));
    }
    {
        float complex value=csinhf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),1.40581625043146825625116639127211772368590104L,3e-6L) && close_to(cimagf(value),0.905358634420957255294690433769712797168098735L,3e-6L));
    }
    {
        double complex value=csinh(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),1.40581625043146825625116639127211772368590104L,1e-14L) && close_to(cimag(value),0.905358634420957255294690433769712797168098735L,1e-14L));
    }
    {
        long double complex value=csinhl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),1.40581625043146825625116639127211772368590104L,4e-18L) && close_to(cimagl(value),0.905358634420957255294690433769712797168098735L,4e-18L));
    }
    {
        float complex value=csinhf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),-0.0178690883978050590956850951668649855146561206L,3e-6L) && close_to(cimagf(value),1.0288293962476211001525863812956301654887431L,3e-6L));
    }
    {
        double complex value=csinh(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),-0.0178690883978050590956850951668649855146561206L,1e-14L) && close_to(cimag(value),1.0288293962476211001525863812956301654887431L,1e-14L));
    }
    {
        long double complex value=csinhl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),-0.0178690883978050590956850951668649855146561206L,4e-18L) && close_to(cimagl(value),1.0288293962476211001525863812956301654887431L,4e-18L));
    }
    {
        float complex value=ctanhf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),0.906724804319430975975073174282573905636106695L,3e-6L) && close_to(cimagf(value),0.126108566484234388557737652634071396294687203L,3e-6L));
    }
    {
        double complex value=ctanh(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),0.906724804319430975975073174282573905636106695L,1e-14L) && close_to(cimag(value),0.126108566484234388557737652634071396294687203L,1e-14L));
    }
    {
        long double complex value=ctanhl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),0.906724804319430975975073174282573905636106695L,4e-18L) && close_to(cimagl(value),0.126108566484234388557737652634071396294687203L,4e-18L));
    }
    {
        float complex value=ctanhf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),-3.78610893681477386969225701878307639982611062L,3e-6L) && close_to(cimagf(value),1.02533206122933924267116067967976855694089752L,3e-6L));
    }
    {
        double complex value=ctanh(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),-3.78610893681477386969225701878307639982611062L,1e-14L) && close_to(cimag(value),1.02533206122933924267116067967976855694089752L,1e-14L));
    }
    {
        long double complex value=ctanhl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),-3.78610893681477386969225701878307639982611062L,4e-18L) && close_to(cimagl(value),1.02533206122933924267116067967976855694089752L,4e-18L));
    }
    {
        float complex value=cexpf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),3.06306411448538295385304363039849476512491204L,3e-6L) && close_to(cimagf(value),1.67335955229453010310323295353055169266708038L,3e-6L));
    }
    {
        double complex value=cexp(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),3.06306411448538295385304363039849476512491204L,1e-14L) && close_to(cimag(value),1.67335955229453010310323295353055169266708038L,1e-14L));
    }
    {
        long double complex value=cexpl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),3.06306411448538295385304363039849476512491204L,4e-18L) && close_to(cimagl(value),1.67335955229453010310323295353055169266708038L,4e-18L));
    }
    {
        float complex value=cexpf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),0.0550901880510869127531752201258952393672766944L,3e-6L) && close_to(cimagf(value),0.776849876677038099885713975895851206199611406L,3e-6L));
    }
    {
        double complex value=cexp(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),0.0550901880510869127531752201258952393672766944L,1e-14L) && close_to(cimag(value),0.776849876677038099885713975895851206199611406L,1e-14L));
    }
    {
        long double complex value=cexpl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),0.0550901880510869127531752201258952393672766944L,4e-18L) && close_to(cimagl(value),0.776849876677038099885713975895851206199611406L,4e-18L));
    }
    {
        float complex value=clogf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),0.297353553873346394757171773264602666596256188L,3e-6L) && close_to(cimagf(value),0.380506377112364886303587916810433104497405714L,3e-6L));
    }
    {
        double complex value=clog(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),0.297353553873346394757171773264602666596256188L,1e-14L) && close_to(cimag(value),0.380506377112364886303587916810433104497405714L,1e-14L));
    }
    {
        long double complex value=clogl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),0.297353553873346394757171773264602666596256188L,4e-18L) && close_to(cimagl(value),0.380506377112364886303587916810433104497405714L,4e-18L));
    }
    {
        float complex value=clogf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),0.419164595202221603349583592599370445799038525L,3e-6L) && close_to(cimagf(value),1.73594500420952345751044998128369489609697136L,3e-6L));
    }
    {
        double complex value=clog(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),0.419164595202221603349583592599370445799038525L,1e-14L) && close_to(cimag(value),1.73594500420952345751044998128369489609697136L,1e-14L));
    }
    {
        long double complex value=clogl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),0.419164595202221603349583592599370445799038525L,4e-18L) && close_to(cimagl(value),1.73594500420952345751044998128369489609697136L,4e-18L));
    }
    {
        float complex value=conjf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),1.25L,3e-6L) && close_to(cimagf(value),-0.5L,3e-6L));
    }
    {
        double complex value=conj(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),1.25L,1e-14L) && close_to(cimag(value),-0.5L,1e-14L));
    }
    {
        long double complex value=conjl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),1.25L,4e-18L) && close_to(cimagl(value),-0.5L,4e-18L));
    }
    {
        float complex value=conjf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),-0.25L,3e-6L) && close_to(cimagf(value),-1.5L,3e-6L));
    }
    {
        double complex value=conj(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),-0.25L,1e-14L) && close_to(cimag(value),-1.5L,1e-14L));
    }
    {
        long double complex value=conjl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),-0.25L,4e-18L) && close_to(cimagl(value),-1.5L,4e-18L));
    }
    {
        float complex value=cprojf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),1.25L,3e-6L) && close_to(cimagf(value),0.5L,3e-6L));
    }
    {
        double complex value=cproj(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),1.25L,1e-14L) && close_to(cimag(value),0.5L,1e-14L));
    }
    {
        long double complex value=cprojl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),1.25L,4e-18L) && close_to(cimagl(value),0.5L,4e-18L));
    }
    {
        float complex value=cprojf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),-0.25L,3e-6L) && close_to(cimagf(value),1.5L,3e-6L));
    }
    {
        double complex value=cproj(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),-0.25L,1e-14L) && close_to(cimag(value),1.5L,1e-14L));
    }
    {
        long double complex value=cprojl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),-0.25L,4e-18L) && close_to(cimagl(value),1.5L,4e-18L));
    }
    {
        float complex value=csqrtf(CMPLXF(1.25,0.5));
        CHECK(close_to(crealf(value),1.13936192708542486381460480559168158733800088L,3e-6L) && close_to(cimagf(value),0.219421058451127256215360629019803466744367818L,3e-6L));
    }
    {
        double complex value=csqrt(CMPLX(1.25,0.5));
        CHECK(close_to(creal(value),1.13936192708542486381460480559168158733800088L,1e-14L) && close_to(cimag(value),0.219421058451127256215360629019803466744367818L,1e-14L));
    }
    {
        long double complex value=csqrtl(CMPLXL(1.25,0.5));
        CHECK(close_to(creall(value),1.13936192708542486381460480559168158733800088L,4e-18L) && close_to(cimagl(value),0.219421058451127256215360629019803466744367818L,4e-18L));
    }
    {
        float complex value=csqrtf(CMPLXF(-0.25,1.5));
        CHECK(close_to(crealf(value),0.797085513785865676313813314432984294931469258L,3e-6L) && close_to(cimagf(value),0.940927901747672408305993309315298117539652917L,3e-6L));
    }
    {
        double complex value=csqrt(CMPLX(-0.25,1.5));
        CHECK(close_to(creal(value),0.797085513785865676313813314432984294931469258L,1e-14L) && close_to(cimag(value),0.940927901747672408305993309315298117539652917L,1e-14L));
    }
    {
        long double complex value=csqrtl(CMPLXL(-0.25,1.5));
        CHECK(close_to(creall(value),0.797085513785865676313813314432984294931469258L,4e-18L) && close_to(cimagl(value),0.940927901747672408305993309315298117539652917L,4e-18L));
    }
    {
        float complex value=cpowf(CMPLXF(1.25,0.5),CMPLXF(1.5,-0.25));
        CHECK(close_to(crealf(value),1.51061899912448632555670582322355553996269918L,3e-6L) && close_to(cimagf(value),0.818248878211867664259066016383551540585057926L,3e-6L));
    }
    {
        double complex value=cpow(CMPLX(1.25,0.5),CMPLX(1.5,-0.25));
        CHECK(close_to(creal(value),1.51061899912448632555670582322355553996269918L,1e-14L) && close_to(cimag(value),0.818248878211867664259066016383551540585057926L,1e-14L));
    }
    {
        long double complex value=cpowl(CMPLXL(1.25,0.5),CMPLXL(1.5,-0.25));
        CHECK(close_to(creall(value),1.51061899912448632555670582322355553996269918L,4e-18L) && close_to(cimagl(value),0.818248878211867664259066016383551540585057926L,4e-18L));
    }
    {
        float complex value=cpowf(CMPLXF(-0.25,1.5),CMPLXF(1.5,-0.25));
        CHECK(close_to(crealf(value),-2.31721229435397921111552174352367926748904234L,3e-6L) && close_to(cimagf(value),1.73416543634298850641521278320912332780074864L,3e-6L));
    }
    {
        double complex value=cpow(CMPLX(-0.25,1.5),CMPLX(1.5,-0.25));
        CHECK(close_to(creal(value),-2.31721229435397921111552174352367926748904234L,1e-14L) && close_to(cimag(value),1.73416543634298850641521278320912332780074864L,1e-14L));
    }
    {
        long double complex value=cpowl(CMPLXL(-0.25,1.5),CMPLXL(1.5,-0.25));
        CHECK(close_to(creall(value),-2.31721229435397921111552174352367926748904234L,4e-18L) && close_to(cimagl(value),1.73416543634298850641521278320912332780074864L,4e-18L));
    }
    CHECK(close_to(cabsf(CMPLXF(1.25,0.5)),1.34629120178362600781267762288508238907378004L,3e-6L));
    CHECK(close_to(cabs(CMPLX(1.25,0.5)),1.34629120178362600781267762288508238907378004L,1e-14L));
    CHECK(close_to(cabsl(CMPLXL(1.25,0.5)),1.34629120178362600781267762288508238907378004L,4e-18L));
    CHECK(close_to(cargf(CMPLXF(1.25,0.5)),0.380506377112364886303587916810433104497405714L,3e-6L));
    CHECK(close_to(carg(CMPLX(1.25,0.5)),0.380506377112364886303587916810433104497405714L,1e-14L));
    CHECK(close_to(cargl(CMPLXL(1.25,0.5)),0.380506377112364886303587916810433104497405714L,4e-18L));
    CHECK(close_to(crealf(CMPLXF(1.25,0.5)),1.25L,3e-6L));
    CHECK(close_to(creal(CMPLX(1.25,0.5)),1.25L,1e-14L));
    CHECK(close_to(creall(CMPLXL(1.25,0.5)),1.25L,4e-18L));
    CHECK(close_to(cimagf(CMPLXF(1.25,0.5)),0.5L,3e-6L));
    CHECK(close_to(cimag(CMPLX(1.25,0.5)),0.5L,1e-14L));
    CHECK(close_to(cimagl(CMPLXL(1.25,0.5)),0.5L,4e-18L));
    serial_printf("LIBC_MATH_VECTORS: PASS checks=708 precision=100");
    return true;
}
