
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.35;

contract LegoGroth16Verifier {
    error ProofInvalid();
    error NonCanonicalInput();

    // BN254 scalar field order
    uint256 constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 constant ALPHA_X = 13028485826207292909686322951924121692184984050939999718400226330747508561449;
    uint256 constant ALPHA_Y = 2448166938957880732987173304143434310605282714609497181129116790197588058334;

    uint256 constant BETA_NEG_X_0 = 13753674693584523253974614865364261890568465048191111584330659199502841629940;
    uint256 constant BETA_NEG_X_1 = 12101459822352014257055881459206001721059342021568533293479033865788247213453;
    uint256 constant BETA_NEG_Y_0 = 9874585652405873897460146986990222239951139968205039474843195137774076610006;
    uint256 constant BETA_NEG_Y_1 = 5422859349954144985516295776045669902372053332070222083818237448723816287572;

    uint256 constant GAMMA_NEG_X_0 = 17902762378058498964999561158051137362178855805222585240714365842309864684345;
    uint256 constant GAMMA_NEG_X_1 = 19025535950299340533914279898750422305878898769950595087110975339118772516442;
    uint256 constant GAMMA_NEG_Y_0 = 9250380814515945789601195014577265065141539347944627339208241867441951255529;
    uint256 constant GAMMA_NEG_Y_1 = 21582964670342945822184796974111421261407814403746342294468874406665443146489;

    uint256 constant DELTA_NEG_X_0 = 15926456754931810897305526733803372974198467619704725697430362966585878050166;
    uint256 constant DELTA_NEG_X_1 = 14549314183227864279645812981813879705890785347791716411580242119443158935708;
    uint256 constant DELTA_NEG_Y_0 = 4347316272090730800744184358900129827571446933196772598672351061689827705139;
    uint256 constant DELTA_NEG_Y_1 = 12767324190558232909301496830059407333006044043071197444714636641822985134301;

    
    uint256 constant GAMMA_ABC_0_X = 14542162255746708486055596230342465863906296073985112535491440690514076235536;
    uint256 constant GAMMA_ABC_0_Y = 1230562129404120567833976817872752436998299834846860951639688835707052301329;
    uint256 constant GAMMA_ABC_1_X = 8403611498194428628529391016605715975920521841814949316969452362648096938963;
    uint256 constant GAMMA_ABC_1_Y = 9550053684452324968747207989902302233245590291025552104889504611225543511019;
    uint256 constant GAMMA_ABC_2_X = 16099489587712976244827627724371630399674204792326159633872746619374203321129;
    uint256 constant GAMMA_ABC_2_Y = 6460939618459188541082425567712859981324282730120534360289562436450645874587;
    uint256 constant GAMMA_ABC_3_X = 21799982846643117798380836087225937640586215168428190078399446171601488717259;
    uint256 constant GAMMA_ABC_3_Y = 14463032898597710623421686851681626153261407915266333297958616492490500165495;
    uint256 constant GAMMA_ABC_4_X = 8724295888864811450560573678822039665008243357636463961823310622358527249912;
    uint256 constant GAMMA_ABC_4_Y = 3994699319609477940794231571020273846915200315084525647070615080491414130456;
    uint256 constant GAMMA_ABC_5_X = 12624555778701189144567552576362907777749409942029076997027252218867474446862;
    uint256 constant GAMMA_ABC_5_Y = 16985756418825380060865336785465605331748536158365561070501977332301053112457;
    uint256 constant GAMMA_ABC_6_X = 5716975531434363748358789901761652184077103805602680079663875426731827818649;
    uint256 constant GAMMA_ABC_6_Y = 18197672912162325757777636753312776210517193309422854392702778901688045543203;
    uint256 constant GAMMA_ABC_7_X = 21089666980014121986411029235946952531210385347993035573212331555430259413325;
    uint256 constant GAMMA_ABC_7_Y = 21220513431685374407208363345486594997810904170465559203558898787529074344933;
    uint256 constant GAMMA_ABC_8_X = 1389330433140084346242924074693647638416564912644832146431284120035438947748;
    uint256 constant GAMMA_ABC_8_Y = 12639472105806773917508202395412132115600864888332447634449261987849313890619;
    uint256 constant GAMMA_ABC_9_X = 20381327862644672025071551036247876638241595042176564494559612911319660903673;
    uint256 constant GAMMA_ABC_9_Y = 16631180673496857012980154412339837540596311002515189176857101991038365091436;
    uint256 constant GAMMA_ABC_10_X = 21386560440189873906791157384190088905843796748635858527824924432492815273192;
    uint256 constant GAMMA_ABC_10_Y = 9415647375855677201880811670834557820006871949200709687071534564958915058412;
    uint256 constant GAMMA_ABC_11_X = 10498046223374615461666884572501031261152933693742654497557408209635453392904;
    uint256 constant GAMMA_ABC_11_Y = 5522224043361401111012481595543901099835364100891749893119444127706294768742;
    uint256 constant GAMMA_ABC_12_X = 21292767661658976172784467519733255930923951941449572667726051196312067167551;
    uint256 constant GAMMA_ABC_12_Y = 4576694086140874090632603965877867764836462812656126096461006827249830008908;
    uint256 constant GAMMA_ABC_13_X = 107326798635994831852325233835439133020695683506377279352591137391625038969;
    uint256 constant GAMMA_ABC_13_Y = 4858557552976051166427792492643828293081951149284027962339725911662340569841;
    uint256 constant GAMMA_ABC_14_X = 4965110953467006504381646344121685368955683737581589239041366440509154227355;
    uint256 constant GAMMA_ABC_14_Y = 5993759591855287121831183910881379488400938119633584920497485933038176980927;
    uint256 constant GAMMA_ABC_15_X = 18007205904059883144094712592479759952171580321197323758244329156231236098099;
    uint256 constant GAMMA_ABC_15_Y = 5633986812209613075535127543885046290395318401585206447591866172501738233622;
    uint256 constant GAMMA_ABC_16_X = 15876422582710347855053542454308509454627093863640495798377927927244229103253;
    uint256 constant GAMMA_ABC_16_Y = 11397995620106766851363728045348960969213780682629337668797783083638982556713;
    uint256 constant GAMMA_ABC_17_X = 13389034111780901172985683816027183116643395579879856275686293544649498229965;
    uint256 constant GAMMA_ABC_17_Y = 21462437062257163246442089925357426829579696815427899199460438656737353182840;
    uint256 constant GAMMA_ABC_18_X = 14055334100234829074518542706159853771819457953553294012980187746454710353478;
    uint256 constant GAMMA_ABC_18_Y = 15321520718997160345880512571432513208041120037277374606285841349658993496609;
    uint256 constant GAMMA_ABC_19_X = 19974802624933179127811271803404041122030345822961577320749591616076090428105;
    uint256 constant GAMMA_ABC_19_Y = 11114329563567164152216568372675034824502222447561379032490721041202946176023;
    uint256 constant GAMMA_ABC_20_X = 20780206495662220688155894251931625260174055685646118006753669911746705688285;
    uint256 constant GAMMA_ABC_20_Y = 13077543172690189068941344329971083126862397521266365525854941624212756635389;
    uint256 constant GAMMA_ABC_21_X = 8196681747649093530769247973160006451749205993391132024629112399731594858415;
    uint256 constant GAMMA_ABC_21_Y = 19668737313542197161078876567379266867848876233439812349001774911373820128683;
    uint256 constant GAMMA_ABC_22_X = 3146916437688374625536375500871059210408810487351776138957264116671648687664;
    uint256 constant GAMMA_ABC_22_Y = 16823321902254670476540639017529048204268921394148194050498348452897743625729;
    uint256 constant GAMMA_ABC_23_X = 18184335132524688256007513875199920417284251762212651863320986302580233421643;
    uint256 constant GAMMA_ABC_23_Y = 5182400721895788262957555389114819522436458457404165326913558958544648873421;
    uint256 constant GAMMA_ABC_24_X = 1278027492240950371705001544991408001139950395737921312785088098440373871335;
    uint256 constant GAMMA_ABC_24_Y = 7349707981797622793107781731685013421371537588629636767056965241983741252905;
    uint256 constant GAMMA_ABC_25_X = 6214788623484870724663036134281575330892748474218560627335208609950755009827;
    uint256 constant GAMMA_ABC_25_Y = 19072337992423232704295290624972257444089452205955022098685076939206116447550;
    uint256 constant GAMMA_ABC_26_X = 12257695096414425318066468296385044485179051265526591881017066067212826138395;
    uint256 constant GAMMA_ABC_26_Y = 19710084076286336061596677506976513455824088377124341967672224899718162554115;
    uint256 constant GAMMA_ABC_27_X = 21961793577610950140609793383151867792781903937307688072922068658508911057;
    uint256 constant GAMMA_ABC_27_Y = 15713890509088127280372528640945644955078766868313734435650188741930217120268;
    uint256 constant GAMMA_ABC_28_X = 19175575019940101692380031078454198605483456160969272122030099438457001981602;
    uint256 constant GAMMA_ABC_28_Y = 3769492646652013132806802149248813247941188929493264101915804215159210104872;
    uint256 constant GAMMA_ABC_29_X = 4784259866945239776907980242059234326158984605236809873425372992320209998188;
    uint256 constant GAMMA_ABC_29_Y = 15423436889629126656981624128585717671916519256843159842094755908362932176354;
    uint256 constant GAMMA_ABC_30_X = 7390877776831613593462786822922780371560361598918137510819677379538823189987;
    uint256 constant GAMMA_ABC_30_Y = 2660108661935056177273912104133058040093955792944171545569039230500456969309;
    uint256 constant GAMMA_ABC_31_X = 487308437877853045270312197894956630709843962536598105290226937721077991678;
    uint256 constant GAMMA_ABC_31_Y = 5375940496256539620091708826333692002870227095710945442181328028206307780607;
    uint256 constant GAMMA_ABC_32_X = 11660262580759548197212708440563640767540153286910629505117900095960549498136;
    uint256 constant GAMMA_ABC_32_Y = 21867594766119614158056000022950873659846410391084713880216901455904037724875;
    uint256 constant GAMMA_ABC_33_X = 6914518205635862803163504197315424410261526649038884433382238993411589132963;
    uint256 constant GAMMA_ABC_33_Y = 16959297152192328515769119666740920363429446570718962891788961243518457799003;
    uint256 constant GAMMA_ABC_34_X = 16624949610150669409807568652215477834914879111986198045212401211802190105903;
    uint256 constant GAMMA_ABC_34_Y = 18069460047176856115358854414875524018125759848541192077026586402686176438231;
    uint256 constant GAMMA_ABC_35_X = 1614783169089812501837947742514410019056411303967623598990066830661013861112;
    uint256 constant GAMMA_ABC_35_Y = 18229434315682523545270376552036492546074813004934795481606948903447365932101;
    uint256 constant GAMMA_ABC_36_X = 17929279573399799870689250470527241372297645111120194257110922482413530485841;
    uint256 constant GAMMA_ABC_36_Y = 16240348724064502618621728637140042749345198846337587665313556554014426098291;
    uint256 constant GAMMA_ABC_37_X = 676285124912724010009149145906144962654015543755184247075849571350716754287;
    uint256 constant GAMMA_ABC_37_Y = 21503551007174691547153587865771502394691858502667308706542642959201136738303;
    uint256 constant GAMMA_ABC_38_X = 15385182383887012975875835368219727685825208793600281981363313471851109860846;
    uint256 constant GAMMA_ABC_38_Y = 21450752640164461628880461245596995230553099942667422543373750843730765236657;
    uint256 constant GAMMA_ABC_39_X = 6787171073904109040765088947709568978160679021410792095601426645771104173602;
    uint256 constant GAMMA_ABC_39_Y = 9931766857930826599106530609467512496804545978453355646550384346387906411898;
    uint256 constant GAMMA_ABC_40_X = 2582720388483630980850668138900410274558907793841835531303020396943477780579;
    uint256 constant GAMMA_ABC_40_Y = 7518621184475711890530210843053304529427471175783934355853561177712507978680;

    
    uint256 constant LINK_C_0_X_0 = 5169665655820391245665352849323850592213422251816376460129912779235194244920;
    uint256 constant LINK_C_0_X_1 = 7153377691602867477649643925151985896175293037364795764739275569075190629149;
    uint256 constant LINK_C_0_Y_0 = 1044788292323763247283817337593370117453769299872426466129755647038511089307;
    uint256 constant LINK_C_0_Y_1 = 19855860629951419201366339185673130589900215921315022058599646044796786059414;
    uint256 constant LINK_C_1_X_0 = 12793751035147129610870323658554312313673074903984139292619865898786062282478;
    uint256 constant LINK_C_1_X_1 = 9170315187811293163941591252190137042247056151633574713072454934068628582834;
    uint256 constant LINK_C_1_Y_0 = 12116915080189368147429407035204088152738635147012673265665786754023594573389;
    uint256 constant LINK_C_1_Y_1 = 18630379034900287509984500801922130344568332627269988107613990295296735857731;
    uint256 constant LINK_C_2_X_0 = 20041731048518481766370309172460448067565398945820154636882609555094197933452;
    uint256 constant LINK_C_2_X_1 = 15665637964608553432826491304458089068401575080469514487583868302453467203498;
    uint256 constant LINK_C_2_Y_0 = 5477873449537007487649844088595269299455817309515341132339554447096723912266;
    uint256 constant LINK_C_2_Y_1 = 9279600097607776007460715154544013862223942596311518340590214909302893232910;

    uint256 constant LINK_A_NEG_X_0 = 20557870258598423874429813679620859376731466813556455567783592293015368071746;
    uint256 constant LINK_A_NEG_X_1 = 8298880787716458205523493646827727263377919941720547466422694828759819683883;
    uint256 constant LINK_A_NEG_Y_0 = 15577683618622941716372904545403742957110961493344819107098381981852854790604;
    uint256 constant LINK_A_NEG_Y_1 = 17256892400086414926121087491783630484101602889779633190571084113477708728765;

    function verifyProof(
        uint256[40] calldata x,
        uint256[4] calldata c,
        uint256[12] calldata proof
    ) public view {
        for (uint256 k = 0; k < 40; k++) {
            if (x[k] >= R) {
                revert NonCanonicalInput();
            }
        }

        bool ok = true;
        uint256 pub_x;
        uint256 pub_y;

        assembly ("memory-safe") {
            let f := mload(0x40)

            // Public input MSM
            mstore(f, GAMMA_ABC_0_X)
            mstore(add(f, 0x20), GAMMA_ABC_0_Y)
            
            mstore(add(f, 0x40), GAMMA_ABC_1_X)
            mstore(add(f, 0x60), GAMMA_ABC_1_Y)
            mstore(add(f, 0x80), calldataload(add(x, 0)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_2_X)
            mstore(add(f, 0x60), GAMMA_ABC_2_Y)
            mstore(add(f, 0x80), calldataload(add(x, 32)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_3_X)
            mstore(add(f, 0x60), GAMMA_ABC_3_Y)
            mstore(add(f, 0x80), calldataload(add(x, 64)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_4_X)
            mstore(add(f, 0x60), GAMMA_ABC_4_Y)
            mstore(add(f, 0x80), calldataload(add(x, 96)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_5_X)
            mstore(add(f, 0x60), GAMMA_ABC_5_Y)
            mstore(add(f, 0x80), calldataload(add(x, 128)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_6_X)
            mstore(add(f, 0x60), GAMMA_ABC_6_Y)
            mstore(add(f, 0x80), calldataload(add(x, 160)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_7_X)
            mstore(add(f, 0x60), GAMMA_ABC_7_Y)
            mstore(add(f, 0x80), calldataload(add(x, 192)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_8_X)
            mstore(add(f, 0x60), GAMMA_ABC_8_Y)
            mstore(add(f, 0x80), calldataload(add(x, 224)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_9_X)
            mstore(add(f, 0x60), GAMMA_ABC_9_Y)
            mstore(add(f, 0x80), calldataload(add(x, 256)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_10_X)
            mstore(add(f, 0x60), GAMMA_ABC_10_Y)
            mstore(add(f, 0x80), calldataload(add(x, 288)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_11_X)
            mstore(add(f, 0x60), GAMMA_ABC_11_Y)
            mstore(add(f, 0x80), calldataload(add(x, 320)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_12_X)
            mstore(add(f, 0x60), GAMMA_ABC_12_Y)
            mstore(add(f, 0x80), calldataload(add(x, 352)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_13_X)
            mstore(add(f, 0x60), GAMMA_ABC_13_Y)
            mstore(add(f, 0x80), calldataload(add(x, 384)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_14_X)
            mstore(add(f, 0x60), GAMMA_ABC_14_Y)
            mstore(add(f, 0x80), calldataload(add(x, 416)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_15_X)
            mstore(add(f, 0x60), GAMMA_ABC_15_Y)
            mstore(add(f, 0x80), calldataload(add(x, 448)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_16_X)
            mstore(add(f, 0x60), GAMMA_ABC_16_Y)
            mstore(add(f, 0x80), calldataload(add(x, 480)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_17_X)
            mstore(add(f, 0x60), GAMMA_ABC_17_Y)
            mstore(add(f, 0x80), calldataload(add(x, 512)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_18_X)
            mstore(add(f, 0x60), GAMMA_ABC_18_Y)
            mstore(add(f, 0x80), calldataload(add(x, 544)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_19_X)
            mstore(add(f, 0x60), GAMMA_ABC_19_Y)
            mstore(add(f, 0x80), calldataload(add(x, 576)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_20_X)
            mstore(add(f, 0x60), GAMMA_ABC_20_Y)
            mstore(add(f, 0x80), calldataload(add(x, 608)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_21_X)
            mstore(add(f, 0x60), GAMMA_ABC_21_Y)
            mstore(add(f, 0x80), calldataload(add(x, 640)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_22_X)
            mstore(add(f, 0x60), GAMMA_ABC_22_Y)
            mstore(add(f, 0x80), calldataload(add(x, 672)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_23_X)
            mstore(add(f, 0x60), GAMMA_ABC_23_Y)
            mstore(add(f, 0x80), calldataload(add(x, 704)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_24_X)
            mstore(add(f, 0x60), GAMMA_ABC_24_Y)
            mstore(add(f, 0x80), calldataload(add(x, 736)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_25_X)
            mstore(add(f, 0x60), GAMMA_ABC_25_Y)
            mstore(add(f, 0x80), calldataload(add(x, 768)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_26_X)
            mstore(add(f, 0x60), GAMMA_ABC_26_Y)
            mstore(add(f, 0x80), calldataload(add(x, 800)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_27_X)
            mstore(add(f, 0x60), GAMMA_ABC_27_Y)
            mstore(add(f, 0x80), calldataload(add(x, 832)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_28_X)
            mstore(add(f, 0x60), GAMMA_ABC_28_Y)
            mstore(add(f, 0x80), calldataload(add(x, 864)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_29_X)
            mstore(add(f, 0x60), GAMMA_ABC_29_Y)
            mstore(add(f, 0x80), calldataload(add(x, 896)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_30_X)
            mstore(add(f, 0x60), GAMMA_ABC_30_Y)
            mstore(add(f, 0x80), calldataload(add(x, 928)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_31_X)
            mstore(add(f, 0x60), GAMMA_ABC_31_Y)
            mstore(add(f, 0x80), calldataload(add(x, 960)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_32_X)
            mstore(add(f, 0x60), GAMMA_ABC_32_Y)
            mstore(add(f, 0x80), calldataload(add(x, 992)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_33_X)
            mstore(add(f, 0x60), GAMMA_ABC_33_Y)
            mstore(add(f, 0x80), calldataload(add(x, 1024)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_34_X)
            mstore(add(f, 0x60), GAMMA_ABC_34_Y)
            mstore(add(f, 0x80), calldataload(add(x, 1056)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_35_X)
            mstore(add(f, 0x60), GAMMA_ABC_35_Y)
            mstore(add(f, 0x80), calldataload(add(x, 1088)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_36_X)
            mstore(add(f, 0x60), GAMMA_ABC_36_Y)
            mstore(add(f, 0x80), calldataload(add(x, 1120)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_37_X)
            mstore(add(f, 0x60), GAMMA_ABC_37_Y)
            mstore(add(f, 0x80), calldataload(add(x, 1152)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_38_X)
            mstore(add(f, 0x60), GAMMA_ABC_38_Y)
            mstore(add(f, 0x80), calldataload(add(x, 1184)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_39_X)
            mstore(add(f, 0x60), GAMMA_ABC_39_Y)
            mstore(add(f, 0x80), calldataload(add(x, 1216)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))
            mstore(add(f, 0x40), GAMMA_ABC_40_X)
            mstore(add(f, 0x60), GAMMA_ABC_40_Y)
            mstore(add(f, 0x80), calldataload(add(x, 1248)))
            ok := and(ok, staticcall(gas(), 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40))
            ok := and(ok, staticcall(gas(), 0x06, f, 0x80, f, 0x40))

            pub_x := mload(f)
            pub_y := mload(add(f, 0x20))

            // A, B
            calldatacopy(f, proof, 0xc0)

            // C, -δ
            calldatacopy(add(f, 0xc0), add(proof, 0xc0), 0x40)
            mstore(add(f, 0x100), DELTA_NEG_X_1)
            mstore(add(f, 0x120), DELTA_NEG_X_0)
            mstore(add(f, 0x140), DELTA_NEG_Y_1)
            mstore(add(f, 0x160), DELTA_NEG_Y_0)

            // α, -β
            mstore(add(f, 0x180), ALPHA_X)
            mstore(add(f, 0x1a0), ALPHA_Y)
            mstore(add(f, 0x1c0), BETA_NEG_X_1)
            mstore(add(f, 0x1e0), BETA_NEG_X_0)
            mstore(add(f, 0x200), BETA_NEG_Y_1)
            mstore(add(f, 0x220), BETA_NEG_Y_0)

            // pub + D, -γ
            mstore(add(f, 0x240), pub_x)
            mstore(add(f, 0x260), pub_y)
            calldatacopy(add(f, 0x280), add(proof, 0x100), 0x40)
            ok := and(ok, staticcall(gas(), 0x06, add(f, 0x240), 0x80, add(f, 0x240), 0x40))
            mstore(add(f, 0x280), GAMMA_NEG_X_1)
            mstore(add(f, 0x2a0), GAMMA_NEG_X_0)
            mstore(add(f, 0x2c0), GAMMA_NEG_Y_1)
            mstore(add(f, 0x2e0), GAMMA_NEG_Y_0)

            ok := and(ok, staticcall(gas(), 0x08, f, 0x300, f, 0x20))
            ok := and(ok, mload(f))

            // c || D, Link_C
            
            calldatacopy(add(f, 0), add(c, 0), 0x40)
            mstore(add(f, 64), LINK_C_0_X_1)
            mstore(add(f, 96), LINK_C_0_X_0)
            mstore(add(f, 128), LINK_C_0_Y_1)
            mstore(add(f, 160), LINK_C_0_Y_0)
            calldatacopy(add(f, 192), add(c, 64), 0x40)
            mstore(add(f, 256), LINK_C_1_X_1)
            mstore(add(f, 288), LINK_C_1_X_0)
            mstore(add(f, 320), LINK_C_1_Y_1)
            mstore(add(f, 352), LINK_C_1_Y_0)
            calldatacopy(add(f, 384), add(proof, 0x100), 0x40)
            mstore(add(f, 448), LINK_C_2_X_1)
            mstore(add(f, 480), LINK_C_2_X_0)
            mstore(add(f, 512), LINK_C_2_Y_1)
            mstore(add(f, 544), LINK_C_2_Y_0)
            // Link_pi, -Link_A
            calldatacopy(add(f, 576), add(proof, 0x140), 0x40)
            mstore(add(f, 640), LINK_A_NEG_X_1)
            mstore(add(f, 672), LINK_A_NEG_X_0)
            mstore(add(f, 704), LINK_A_NEG_Y_1)
            mstore(add(f, 736), LINK_A_NEG_Y_0)

            ok := and(ok, staticcall(gas(), 0x08, f, 768, f, 0x20))
            ok := and(ok, mload(f))
        }
        if (!ok) {
            revert ProofInvalid();
        }
    }
}