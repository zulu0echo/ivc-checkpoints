// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

/*
    Sonobe's Nova + CycleFold decider verifier.
    Joint effort by 0xPARC & PSE.

    More details at https://github.com/privacy-scaling-explorations/sonobe
    Usage and design documentation at https://privacy-scaling-explorations.github.io/sonobe-docs/

    Uses the https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs
    Groth16 verifier implementation and a KZG10 Solidity template adapted from
    https://github.com/weijiekoh/libkzg.
    Additionally we implement the NovaDecider contract, which combines the
    Groth16 and KZG10 verifiers to verify the zkSNARK proofs coming from
    Nova+CycleFold folding.
*/


/* =============================== */
/* KZG10 verifier methods */
/**
 * @author  Privacy and Scaling Explorations team - pse.dev
 * @dev     Contains utility functions for ops in BN254; in G_1 mostly.
 * @notice  Forked from https://github.com/weijiekoh/libkzg.
 * Among others, a few of the changes we did on this fork were:
 * - Templating the pragma version
 * - Removing type wrappers and use uints instead
 * - Performing changes on arg types
 * - Update some of the `require` statements 
 * - Use the bn254 scalar field instead of checking for overflow on the babyjub prime
 * - In batch checking, we compute auxiliary polynomials and their commitments at the same time.
 */
contract KZG10Verifier {

    // prime of field F_p over which y^2 = x^3 + 3 is defined
    uint256 public constant BN254_PRIME_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 public constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /**
     * @notice  Performs scalar multiplication in G_1.
     * @param   p  G_1 point to multiply
     * @param   s  Scalar to multiply by
     * @return  r  G_1 point p multiplied by scalar s
     */
    function mulScalar(uint256[2] memory p, uint256 s) internal view returns (uint256[2] memory r) {
        uint256[3] memory input;
        input[0] = p[0];
        input[1] = p[1];
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
            switch success
            case 0 { invalid() }
        }
        require(success, "bn254: scalar mul failed");
    }

    /**
     * @notice  Negates a point in G_1.
     * @param   p  G_1 point to negate
     * @return  uint256[2]  G_1 point -p
     */
    function negate(uint256[2] memory p) internal pure returns (uint256[2] memory) {
        if (p[0] == 0 && p[1] == 0) {
            return p;
        }
        return [p[0], BN254_PRIME_FIELD - (p[1] % BN254_PRIME_FIELD)];
    }

    /**
     * @notice  Adds two points in G_1.
     * @param   p1  G_1 point 1
     * @param   p2  G_1 point 2
     * @return  r  G_1 point p1 + p2
     */
    function add(uint256[2] memory p1, uint256[2] memory p2) internal view returns (uint256[2] memory r) {
        bool success;
        uint256[4] memory input = [p1[0], p1[1], p2[0], p2[1]];
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0x80, r, 0x40)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: point add failed");
    }

    /**
     * @notice  Computes the pairing check e(p1, p2) * e(p3, p4) == 1
     * @dev     Note that G_2 points a*i + b are encoded as two elements of F_p, (a, b)
     * @param   a_1  G_1 point 1
     * @param   a_2  G_2 point 1
     * @param   b_1  G_1 point 2
     * @param   b_2  G_2 point 2
     * @return  result  true if pairing check is successful
     */
    function pairing(uint256[2] memory a_1, uint256[2][2] memory a_2, uint256[2] memory b_1, uint256[2][2] memory b_2)
        internal
        view
        returns (bool result)
    {
        uint256[12] memory input = [
            a_1[0],
            a_1[1],
            a_2[0][1], // imaginary part first
            a_2[0][0],
            a_2[1][1], // imaginary part first
            a_2[1][0],
            b_1[0],
            b_1[1],
            b_2[0][1], // imaginary part first
            b_2[0][0],
            b_2[1][1], // imaginary part first
            b_2[1][0]
        ];

        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(sub(gas(), 2000), 8, input, 0x180, out, 0x20)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: pairing failed");

        return out[0] == 1;
    }

    uint256[2] G_1 = [
            3643763148508132918245313801460210387270869463191315186602746678351776062167,
            2591053918989656159465862834800174251588628298843848132816300476608734870149
    ];
    uint256[2][2] G_2 = [
        [
            1889523848926008664124567445262983638037688672303893908900789202616896872075,
            10140100316223981382687906149800782624960286538979124817255474051580340873991
        ],
        [
            5376120285902560325048056102804210640766952821086524023686069779561453756529,
            3824799552181163225121665120877939157622479477618992705386216216490372104051
        ]
    ];
    uint256[2][2] VK = [
        [
            14446534690689958399542605180732777671255044750910809614753500443750348248014,
            2376932765572723992908162444016543295938486501111393305469823461691707906514
        ],
        [
            16855761256115874899130070261111911826408587871533101975435663801540149229695,
            18646011429651639484383374244628887384123661766298896602568543985579883593990
        ]
    ];

    

    /**
     * @notice  Verifies a single point evaluation proof. Function name follows `ark-poly`.
     * @dev     To avoid ops in G_2, we slightly tweak how the verification is done.
     * @param   c  G_1 point commitment to polynomial.
     * @param   pi G_1 point proof.
     * @param   x  Value to prove evaluation of polynomial at.
     * @param   y  Evaluation poly(x).
     * @return  result Indicates if KZG proof is correct.
     */
    function check(uint256[2] calldata c, uint256[2] calldata pi, uint256 x, uint256 y)
        public
        view
        returns (bool result)
    {
        //
        // we want to:
        //      1. avoid gas intensive ops in G2
        //      2. format the pairing check in line with what the evm opcode expects.
        //
        // we can do this by tweaking the KZG check to be:
        //
        //          e(pi, vk - x * g2) = e(c - y * g1, g2) [initial check]
        //          e(pi, vk - x * g2) * e(c - y * g1, g2)^{-1} = 1
        //          e(pi, vk - x * g2) * e(-c + y * g1, g2) = 1 [bilinearity of pairing for all subsequent steps]
        //          e(pi, vk) * e(pi, -x * g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(-x * pi, g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(x * -pi - c + y * g1, g2) = 1 [done]
        //                        |_   rhs_pairing  _|
        //
        uint256[2] memory rhs_pairing =
            add(mulScalar(negate(pi), x), add(negate(c), mulScalar(G_1, y)));
        return pairing(pi, VK, rhs_pairing, G_2);
    }

    function evalPolyAt(uint256[] memory _coefficients, uint256 _index) public pure returns (uint256) {
        uint256 m = BN254_SCALAR_FIELD;
        uint256 result = 0;
        uint256 powerOfX = 1;

        for (uint256 i = 0; i < _coefficients.length; i++) {
            uint256 coeff = _coefficients[i];
            assembly {
                result := addmod(result, mulmod(powerOfX, coeff, m), m)
                powerOfX := mulmod(powerOfX, _index, m)
            }
        }
        return result;
    }

    
}

/* =============================== */
/* Groth16 verifier methods */
/*
    Copyright 2021 0KIMS association.

    * `solidity-verifiers` added comment
        This file is a template built out of [snarkJS](https://github.com/iden3/snarkjs) groth16 verifier.
        See the original ejs template [here](https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs)
    *

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 1619786941986400145102204820060710780562468146632225668713397865878189820040;
    uint256 constant alphay  = 1351279588743842047560766700512245616779040506959180056074259674409243939521;
    uint256 constant betax1  = 6445847800555892397584112630484890328638304012760325364854371429137401156466;
    uint256 constant betax2  = 13682891628454160643535358967386977849158942790287848965999112075261270323426;
    uint256 constant betay1  = 12304820538109187222589127357464899787106563679701508315018850635831732472427;
    uint256 constant betay2  = 4703098585143567939871101059211589958140235243324342460996838927280296073939;
    uint256 constant gammax1 = 10510411774253370621515098531690888889501818554986075344866509576680718724660;
    uint256 constant gammax2 = 13485572946923937238837792327257541823231864315608021396733801216572085780764;
    uint256 constant gammay1 = 907023535912671422348799344015794826420964833030593843401891961530327340844;
    uint256 constant gammay2 = 18832756597635393532538195097144439052141133773505653892012180739098142065950;
    uint256 constant deltax1 = 2580303452580377018895576999494460647952922558836122982015690400337229498126;
    uint256 constant deltax2 = 27092272862417206551355314654916951456688002508414962608610983398952665871;
    uint256 constant deltay1 = 6784095296451568385324594871379920296112043081500397740035853193230582924004;
    uint256 constant deltay2 = 16607633455236224538642831606276897628601923106693564477054886733320242557551;

    
    uint256 constant IC0x = 6070874833993432878441961943968562138476437224249929173227718552793433898665;
    uint256 constant IC0y = 9852356652722815670220015073768357296579913345394106782354801952970750500600;
    
    uint256 constant IC1x = 2642670738540719193742981254711453253667693079993080729507471856245570897419;
    uint256 constant IC1y = 17722943763317496264884092334696879026721149160088670397817091720652002078326;
    
    uint256 constant IC2x = 13891608036027277861245460032623638025055086092210576425054091740951655607504;
    uint256 constant IC2y = 13645442044617882080412626665868347586720162955657388168577586515373180029055;
    
    uint256 constant IC3x = 21841906883533230779220671884764245318392746701771586559359601172980656981303;
    uint256 constant IC3y = 6568023847686048666946289782250781013403304332415669767781937291984260660552;
    
    uint256 constant IC4x = 7516630777698133106739796686181289298403138272043149598454649067338129625847;
    uint256 constant IC4y = 5138710330304100122036180636431781187756128958269306642202952135665536253771;
    
    uint256 constant IC5x = 1924433665435878689866144029913336514037835148997895522292620517837493747871;
    uint256 constant IC5y = 17693268653069506016778533080991301124255135923581806922490957433454399562232;
    
    uint256 constant IC6x = 5794671006254798724967498202211012956678745769535187288144639896860439111604;
    uint256 constant IC6y = 10927870703081390029342594794386500915174823347217005505830998159244262164817;
    
    uint256 constant IC7x = 12124380383597073165037159277522042716597025796824594407615485426117728985439;
    uint256 constant IC7y = 7779534238391167470370448709790232707618159670985602529330600785086088105192;
    
    uint256 constant IC8x = 17751703825962910843319588108996504452459343328775587665393282769721692183308;
    uint256 constant IC8y = 21768699154829022423193229993969050068289166294713626975784405152388099829897;
    
    uint256 constant IC9x = 7139927085884435083808507971460132944909639250423660893791838542005371615649;
    uint256 constant IC9y = 884945537170581770542563692978772964436867423948249556694262924728584506239;
    
    uint256 constant IC10x = 20157656990670500536749491550139343867199894300920056154226039066909521379448;
    uint256 constant IC10y = 19983072770613934900706073176744113922223299861920477665943812312045645218105;
    
    uint256 constant IC11x = 18449961526357158039661442738203370298150213020212401695326463386144590249957;
    uint256 constant IC11y = 1188890885576531886109654629403684538576420688751164515972683747864333875866;
    
    uint256 constant IC12x = 12632980600374343530936661652338304301633449431571202407382756924974054326013;
    uint256 constant IC12y = 11862078049201655732268512667216685944347072775324732126836502218270972094875;
    
    uint256 constant IC13x = 8576740311926769517323882497563260095914661865597581556146236602275342350004;
    uint256 constant IC13y = 7662145906758150398300666490970729404463058770946371612554137948716837712075;
    
    uint256 constant IC14x = 4549653528979920072685684293110486311172186754551977069898573691527929342324;
    uint256 constant IC14y = 12217047685398760225895198801932430783264646242234047225043968645991324710867;
    
    uint256 constant IC15x = 8834303746055579496064047158506099802020137326572750195372012117757296643887;
    uint256 constant IC15y = 18883736293058462601682036924855189790700330505272713529356438332822043493362;
    
    uint256 constant IC16x = 13985756595889134207630163420299396812162481891053636399255928004151086348357;
    uint256 constant IC16y = 10242714784005336531936971803606264556633639696531958140137131050675358068528;
    
    uint256 constant IC17x = 10782890922569514862975332189978922914418779020213697438694297380045896333132;
    uint256 constant IC17y = 4015738591647674080285885817528081968803951988347347853597271541540247842309;
    
    uint256 constant IC18x = 13748506771880327827399987218681322450669826360516381476191476498561721007179;
    uint256 constant IC18y = 16602476956837106665213561104740104961744741146937967311995690381601935961822;
    
    uint256 constant IC19x = 11884767633976177742754421121511423270621183148339116754597105702548788978301;
    uint256 constant IC19y = 9680533289660981583540947069957733798513584081424458892512931176950484856106;
    
    uint256 constant IC20x = 133170592574461086486537604273914183421749119472522252074647139884293829095;
    uint256 constant IC20y = 25402660434365435474845790493345766822110917641437469768480179611360769818;
    
    uint256 constant IC21x = 17311022591399296691662418492563759453819565436973694732894786193763000869994;
    uint256 constant IC21y = 2890810052136302653740157882690910716445621143344681735981944113490166062949;
    
    uint256 constant IC22x = 18705067109358295009497759593916238607325451902380032354791795879790817553590;
    uint256 constant IC22y = 19665252742795069365065483940036218201290765614012977251770980677959865982599;
    
    uint256 constant IC23x = 11100985188326805391270829724631369852576980810166361938366973927668952110287;
    uint256 constant IC23y = 16016328613585180301703702746616022350063152355561577660809202122299742305518;
    
    uint256 constant IC24x = 20269211261274387778570445491182014547205583346397399948458175380596294440891;
    uint256 constant IC24y = 3248401977967483535237859570816469153170874765993609360535388718889570379753;
    
    uint256 constant IC25x = 6461478592461374583784751259745923756912030841454120673419115079457401968086;
    uint256 constant IC25y = 13198393320117341312180076311827166120254730793407452522542151318769380270866;
    
    uint256 constant IC26x = 21380788366839652973605389143138258998365140759228544777567942209261281838124;
    uint256 constant IC26y = 6584755322284200966374956412231869750867250071753149890919419052292132419651;
    
    uint256 constant IC27x = 2538747471920070251683021765695461244650361822282547864784101777430205540905;
    uint256 constant IC27y = 6637528887002885974089439641821325002014602156842237109795426189093018450243;
    
    uint256 constant IC28x = 13600339611838663398958328818734578591058701038892142117091185039267704448146;
    uint256 constant IC28y = 18828085635739629205534117761942983931232714926506660542334402935130000868258;
    
    uint256 constant IC29x = 2330963667033596541823417556668961309379218133464219318911918080270633235305;
    uint256 constant IC29y = 6649946102897989099366279231132255214986996116119113443063853616110105393077;
    
    uint256 constant IC30x = 13427575923801356445790743137792985207015538403555857664351013492008855382107;
    uint256 constant IC30y = 2873551843403794558634223724548363886137129311685461078237852640775361420978;
    
    uint256 constant IC31x = 8165689637308586896678286119237949428753148600583838475986240560307835959409;
    uint256 constant IC31y = 3756646284374810359162877029218104156908679164161877390830347693609826790277;
    
    uint256 constant IC32x = 10783383099260496725571599773984557646503174772421436924263235959759444116877;
    uint256 constant IC32y = 3690806213350119771431871897247909014243778218456635216416855706971323154873;
    
    uint256 constant IC33x = 17602925048939685530438003445779562589940520500367620550698358148626541855934;
    uint256 constant IC33y = 661682294344937479185127938332039834116671805189715891803334220912764689916;
    
    uint256 constant IC34x = 4667878530213178308441848850399422659167271611689160578336219281974663223668;
    uint256 constant IC34y = 10475371189879714918768275674901979121303286339274202846102544019878135966668;
    
    uint256 constant IC35x = 9874160350160469980102866596463800729528728414427839154857199133043909203710;
    uint256 constant IC35y = 17647441646876391937551705348143716144944064889697485266792611923875289919395;
    
    uint256 constant IC36x = 3008281325264337117678903999450611674145210291789829086195958006486198331610;
    uint256 constant IC36y = 17594444871169919068548627134403830071703657662154126285621249986491657696132;
    
    uint256 constant IC37x = 21546320159407082439294794377392477280344533063992281531429402855118552061314;
    uint256 constant IC37y = 14376306097615828592592035406109392270685429797510252559857219158170213700493;
    
    uint256 constant IC38x = 3906037247300517291494237067679452112199611565182915986688190871269901949015;
    uint256 constant IC38y = 8174090493850398000695546615423588647363121875683606195580837715634171654867;
    
    uint256 constant IC39x = 10831393164231998392597797690049318697782209241317279637384506965973963795374;
    uint256 constant IC39y = 10790571172128223664815004460003307798677435482382634107350089611466870377078;
    
    uint256 constant IC40x = 277381949562208784611637406041513610255852883902974787824041090724477464202;
    uint256 constant IC40y = 21436055917902295056746731682526276762788427222794299315288404453797428670336;
    
    uint256 constant IC41x = 8564861552773751437340841624427809016383066583471514601915685540338521739005;
    uint256 constant IC41y = 4153429398377065784051924252873896785323154957217788247709860610127648617495;
    
    uint256 constant IC42x = 7007844185246129568664588912084497967301775459226682709911536121429052266684;
    uint256 constant IC42y = 4473372186533479516941047248720024349505135214174235678770676114841247348802;
    
    
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[42] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))
                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))
                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))
                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))
                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))
                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))
                g1_mulAccC(_pVk, IC38x, IC38y, calldataload(add(pubSignals, 1184)))
                g1_mulAccC(_pVk, IC39x, IC39y, calldataload(add(pubSignals, 1216)))
                g1_mulAccC(_pVk, IC40x, IC40y, calldataload(add(pubSignals, 1248)))
                g1_mulAccC(_pVk, IC41x, IC41y, calldataload(add(pubSignals, 1280)))
                g1_mulAccC(_pVk, IC42x, IC42y, calldataload(add(pubSignals, 1312)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            
            checkField(calldataload(add(_pubSignals, 1056)))
            
            checkField(calldataload(add(_pubSignals, 1088)))
            
            checkField(calldataload(add(_pubSignals, 1120)))
            
            checkField(calldataload(add(_pubSignals, 1152)))
            
            checkField(calldataload(add(_pubSignals, 1184)))
            
            checkField(calldataload(add(_pubSignals, 1216)))
            
            checkField(calldataload(add(_pubSignals, 1248)))
            
            checkField(calldataload(add(_pubSignals, 1280)))
            
            checkField(calldataload(add(_pubSignals, 1312)))
            
            checkField(calldataload(add(_pubSignals, 1344)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            
            return(0, 0x20)
        }
    }
}


/* =============================== */
/* Nova+CycleFold Decider verifier */
/**
 * @notice  Computes the decomposition of a `uint256` into num_limbs limbs of bits_per_limb bits each.
 * @dev     Compatible with sonobe::folding-schemes::folding::circuits::nonnative::nonnative_field_to_field_elements.
 */
library LimbsDecomposition {
    function decompose(uint256 x) internal pure returns (uint256[5] memory) {
        uint256[5] memory limbs;
        for (uint8 i = 0; i < 5; i++) {
            limbs[i] = (x >> (55 * i)) & ((1 << 55) - 1);
        }
        return limbs;
    }
}

/**
 * @author PSE & 0xPARC
 * @title  Interface for the NovaDecider contract hiding proof details.
 * @dev    This interface enables calling the verifyNovaProof function without exposing the proof details.
 */
interface OpaqueDecider {
    /**
     * @notice  Verifies a Nova+CycleFold proof given initial and final IVC states, number of steps and the rest proof inputs concatenated.
     * @dev     This function should simply reorganize arguments and pass them to the proper verification function.
     */
    function verifyOpaqueNovaProofWithInputs(
        uint256 steps, // number of folded steps (i)
        uint256[3] calldata initial_state, // initial IVC state (z0)
        uint256[3] calldata final_state, // IVC state after i steps (zi)
        uint256[25] calldata proof // the rest of the decider inputs
    ) external view returns (bool);

    /**
     * @notice  Verifies a Nova+CycleFold proof given all the proof inputs collected in a single array.
     * @dev     This function should simply reorganize arguments and pass them to the proper verification function.
     */
    function verifyOpaqueNovaProof(uint256[32] calldata proof) external view returns (bool);
}

/**
 * @author  PSE & 0xPARC
 * @title   NovaDecider contract, for verifying Nova IVC SNARK proofs.
 * @dev     This is an askama template which, when templated, features a Groth16 and KZG10 verifiers from which this contract inherits.
 */
contract NovaDecider is Groth16Verifier, KZG10Verifier, OpaqueDecider {
    /**
     * @notice  Computes the linear combination of a and b with r as the coefficient.
     * @dev     All ops are done mod the BN254 scalar field prime
     */
    function rlc(uint256 a, uint256 r, uint256 b) internal pure returns (uint256 result) {
        assembly {
            result := addmod(a, mulmod(r, b, BN254_SCALAR_FIELD), BN254_SCALAR_FIELD)
        }
    }

    /**
     * @notice  Verifies a nova cyclefold proof consisting of two KZG proofs and of a groth16 proof.
     * @dev     The selector of this function is "dynamic", since it depends on `z_len`.
     */
    function verifyNovaProof(
        // inputs are grouped to prevent errors due stack too deep
        uint256[7] calldata i_z0_zi, // [i, z0, zi] where |z0| == |zi|
        uint256[4] calldata U_i_cmW_U_i_cmE, // [U_i_cmW[2], U_i_cmE[2]]
        uint256[2] calldata u_i_cmW, // [u_i_cmW[2]]
        uint256[3] calldata cmT_r, // [cmT[2], r]
        uint256[2] calldata pA, // groth16 
        uint256[2][2] calldata pB, // groth16
        uint256[2] calldata pC, // groth16
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, // [challenge_W, challenge_E, eval_W, eval_E]
        uint256[2][2] calldata kzg_proof // [proof_W, proof_E]
    ) public view returns (bool) {

        require(i_z0_zi[0] >= 2, "Folding: the number of folded steps should be at least 2");

        // from gamma_abc_len, we subtract 1. 
        uint256[42] memory public_inputs; 

        public_inputs[0] = 2187957856056614623299218452687368397396786519762667742528086232267230578664;
        public_inputs[1] = i_z0_zi[0];

        for (uint i = 0; i < 6; i++) {
            public_inputs[2 + i] = i_z0_zi[1 + i];
        }

        {
            // U_i.cmW + r * u_i.cmW
            uint256[2] memory mulScalarPoint = super.mulScalar([u_i_cmW[0], u_i_cmW[1]], cmT_r[2]);
            uint256[2] memory cmW = super.add([U_i_cmW_U_i_cmE[0], U_i_cmW_U_i_cmE[1]], mulScalarPoint);

            {
                uint256[5] memory cmW_x_limbs = LimbsDecomposition.decompose(cmW[0]);
                uint256[5] memory cmW_y_limbs = LimbsDecomposition.decompose(cmW[1]);
        
                for (uint8 k = 0; k < 5; k++) {
                    public_inputs[8 + k] = cmW_x_limbs[k];
                    public_inputs[13 + k] = cmW_y_limbs[k];
                }
            }
        
            require(this.check(cmW, kzg_proof[0], challenge_W_challenge_E_kzg_evals[0], challenge_W_challenge_E_kzg_evals[2]), "KZG: verifying proof for challenge W failed");
        }

        {
            // U_i.cmE + r * cmT
            uint256[2] memory mulScalarPoint = super.mulScalar([cmT_r[0], cmT_r[1]], cmT_r[2]);
            uint256[2] memory cmE = super.add([U_i_cmW_U_i_cmE[2], U_i_cmW_U_i_cmE[3]], mulScalarPoint);

            {
                uint256[5] memory cmE_x_limbs = LimbsDecomposition.decompose(cmE[0]);
                uint256[5] memory cmE_y_limbs = LimbsDecomposition.decompose(cmE[1]);
            
                for (uint8 k = 0; k < 5; k++) {
                    public_inputs[18 + k] = cmE_x_limbs[k];
                    public_inputs[23 + k] = cmE_y_limbs[k];
                }
            }

            require(this.check(cmE, kzg_proof[1], challenge_W_challenge_E_kzg_evals[1], challenge_W_challenge_E_kzg_evals[3]), "KZG: verifying proof for challenge E failed");
        }

        {
            // add challenges
            public_inputs[28] = challenge_W_challenge_E_kzg_evals[0];
            public_inputs[29] = challenge_W_challenge_E_kzg_evals[1];
            public_inputs[30] = challenge_W_challenge_E_kzg_evals[2];
            public_inputs[31] = challenge_W_challenge_E_kzg_evals[3];

            uint256[5] memory cmT_x_limbs;
            uint256[5] memory cmT_y_limbs;
        
            cmT_x_limbs = LimbsDecomposition.decompose(cmT_r[0]);
            cmT_y_limbs = LimbsDecomposition.decompose(cmT_r[1]);
        
            for (uint8 k = 0; k < 5; k++) {
                public_inputs[28 + 4 + k] = cmT_x_limbs[k]; 
                public_inputs[33 + 4 + k] = cmT_y_limbs[k];
            }

            bool success_g16 = this.verifyProof(pA, pB, pC, public_inputs);
            require(success_g16 == true, "Groth16: verifying proof failed");
        }

        return(true);
    }

    /**
     * @notice  Verifies a Nova+CycleFold proof given initial and final IVC states, number of steps and the rest proof inputs concatenated.
     * @dev     Simply reorganization of arguments and call to the `verifyNovaProof` function.
     */
    function verifyOpaqueNovaProofWithInputs(
        uint256 steps,
        uint256[3] calldata initial_state,
        uint256[3] calldata final_state,
        uint256[25] calldata proof
    ) public override view returns (bool) {
        uint256[1 + 2 * 3] memory i_z0_zi;
        i_z0_zi[0] = steps;
        for (uint256 i = 0; i < 3; i++) {
            i_z0_zi[i + 1] = initial_state[i];
            i_z0_zi[i + 1 + 3] = final_state[i];
        }

        uint256[4] memory U_i_cmW_U_i_cmE = [proof[0], proof[1], proof[2], proof[3]];
        uint256[2] memory u_i_cmW = [proof[4], proof[5]];
        uint256[3] memory cmT_r = [proof[6], proof[7], proof[8]];
        uint256[2] memory pA = [proof[9], proof[10]];
        uint256[2][2] memory pB = [[proof[11], proof[12]], [proof[13], proof[14]]];
        uint256[2] memory pC = [proof[15], proof[16]];
        uint256[4] memory challenge_W_challenge_E_kzg_evals = [proof[17], proof[18], proof[19], proof[20]];
        uint256[2][2] memory kzg_proof = [[proof[21], proof[22]], [proof[23], proof[24]]];

        return this.verifyNovaProof(
            i_z0_zi,
            U_i_cmW_U_i_cmE,
            u_i_cmW,
            cmT_r,
            pA,
            pB,
            pC,
            challenge_W_challenge_E_kzg_evals,
            kzg_proof
        );
    }

    /**
     * @notice  Verifies a Nova+CycleFold proof given all proof inputs concatenated.
     * @dev     Simply reorganization of arguments and call to the `verifyNovaProof` function.
     */
    function verifyOpaqueNovaProof(uint256[32] calldata proof) public override view returns (bool) {
        uint256[3] memory z0;
        uint256[3] memory zi;
        for (uint256 i = 0; i < 3; i++) {
            z0[i] = proof[i + 1];
            zi[i] = proof[i + 1 + 3];
        }

        uint256[25] memory extracted_proof;
        for (uint256 i = 0; i < 25; i++) {
            extracted_proof[i] = proof[7 + i];
        }

        return this.verifyOpaqueNovaProofWithInputs(proof[0], z0, zi, extracted_proof);
    }
}