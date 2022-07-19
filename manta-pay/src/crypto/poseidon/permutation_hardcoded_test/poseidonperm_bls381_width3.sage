# adapted from https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/poseidonperm_x5_255_3.sage
# Targeting BLS12-381 curve and WIDTH3 permutation with input as [3,1,2].

# M = 128
N = 765
arity = 2
t = arity + 1
n = int(N / t)
R_F = 8
R_P = 55
prime = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
F = GF(prime)
round_constants = ['0x5c55b2970538d11b6c956b3f4401f8ba19e023c097388ad34f8d19e2c4fa2f93', '0x1c07c723706e180aba8f86d0b2d1f1c8f09331f35902cbd21a1b77d100157c2a', '0x069939832dd245af3bc2a5167d58811814a2fa1f5399895e67b3cfd636b7885c', '0x05f27ee938066d35d45cc253ee33cf58db658a6dbd04efa529614b6c709b56c5', '0x4c33b40f0116518c7a967258ac518eb9de652c91338d6a2a137a6173657a37de', '0x3f1ca7c11e28100e56ebe179159c4d0fe8ee745e37cee6c400490b96214f3610', '0x5ef4d47dcfa0cca0e7f17d5501e60c6e08294231378815ed4e13786c7ffec2e9', '0x020cf330725eb29ea090cb84e8240606f9f3892f2cf79908fab71a06e2774068', '0x4bd72f77a0ec97d039014400ee028a2ef736ca19c4bc3a28f82ffd6de73517fb', '0x08544715db1335dd6fed642621bb8f1bf03521793b64c5c22d28bd46c1e548a5', '0x26babfec1c990be50c2de2f3dec4aed0a83483a2ac231f356414de7a8eac076e', '0x1fcbdb56272aae4626f787463517d15576f727389ee18dbf8c7b24ddbeaf05f4', '0x63d058167faab807b365f1035126b4a5fd9c48b4c6d58749091f3dee25829bdb', '0x24024a3658da9e97e94c38ad40326b46e3715febba9b359bbc705f3c6da65a46', '0x6211c82cae397276172cab467a4df2783b35d693cff1374da2c3bdfd744e4b84', '0x5d03149dd25ef7219398e885064a54d803d39703e17a78ed675ac632d707b9c5', '0x16748f1925711b91a943900486ea9f692cf937081027c719233a02aad5beaf0d', '0x1cbfe7855c0e20303f260536bec1c85913bd7c803e54a80c08ba4f292da6b952', '0x4351ec0693e43957430b2bf30506d65111bf0311a63a54faaec02ee7e37382d7', '0x2f57d57a9f4e7f65afffdeaf118ddc578ff54986f0c6423be67ef642f35dc0bb', '0x2cbd03dae30133f99798e97142f96546c14ab55a9f71b08d23e632df261b95fb', '0x1c61b2013f74d87e5f4cae0bb683f0cf9ac28b85d03a36948797f8bef61f2c7e', '0x6879c019190734389768d3260afbd4f4419beaca3a9bd4295ef3746452c4e342', '0x56fce4f995b862924aa988ab85cf42dffd90b071016f6523d7b61d634f15f8a5', '0x435db32a86baf237109df01ac09b4ab7ece907723a8624796615ce6e6b563e30', '0x0770749c219fdde970efe9412b405e3ea8496956dcfd676897c3b11a475399fb', '0x0ea1cebad5b1635acd5f1d0ecfb3817f2efe75f63758cfce88e05f9d3917eb26', '0x623ae81720dada6f12d9b6417dda26e9b4f3ef60bb9ff736a0cf455b4c31ce58', '0x61d5b908cba8b438fdf00b2e4f9ef02092580541a78b22d0c0dbe5e549114989', '0x5e9e9fcb0e33769be5674f7621085bd537874eef98425d2fc5c889c0dcf10396', '0x4a737cec75595692230acee973defef29aa3280cb7f1c2b7fc501509733d7bf6', '0x64a7e40c1c26c0405ba63459bc6884750b13423fe514b7d66687b5da670f9573', '0x0aaa44bdb34f82e83f8521c97fd37f064117d2103bed43fa5e59b04d835d5409', '0x63c65b4f4b26b83a4587a0acb53d256eec1f71e66430873461a07c8205bfae7d', '0x1ac0837dd6c2a1750065158c02a73a1a7c9dae95b398e3bc1d73301c1d88cf8c', '0x3143fcbf9d497bc69c52950c3b4d7aebd70e793113574d854ff54f1426c4aa10', '0x3f118f63a010aa4741445d20ef180d666d026194570cc940355f4e56d6bdf905', '0x58caa9c5d698e9c975ab58959fe5e8e0ef0aefe562ebd159b7906db28d733887', '0x58338e3bbf7ca37f156ccf6768651a46d9e3f1aa893235f2248cc391a1c6cd00', '0x44abfa54ec339ad7287aa797148b62aee387672a1d72552b6bde9ab6bf47fc2a', '0x256d0e9133c648964ce3d5583c83dfc9a2774dd8843c940b6770c882630a02f8', '0x3845b63cc6924f105234fbe673546159a9f3b6e2780c7e8d1960b6f4e8b0d27d', '0x2085d78da59214da929d4f5adbf1cfb30d95efd5a29157fe7af9ba27e1c9b807', '0x1edf4b87504c156d2ce81da4f636c7709ee1c7b99f13efd4719f4621e308ea9e', '0x07add95745f693d1119f698f0fe13a22de35f649866874d5821c306bf4a6660f', '0x30ca51700e241210c8d85c4cee8526861e7fe9d3458ee4083a9a5ee9ad59dc9b', '0x4570572601ac5e7f1e8008a891e79747cd0e19376bc6739e7ee581b77e2b953c', '0x23fcb6e2ff8528204b9296493a22728b91c88ad920ca7060d254f59261850af5', '0x0368aff3d7328a0e64a83bbe2611e66e51b45567c6e5aed83632dde7e90bdb7c', '0x72b58a608f54d0d735bcf1aeca8f8ba2b8a7782cdce485014c69bad3b9e6f254', '0x218125d0de84f12ddea67ed5a29cfdf4bd93ab44c230c8107d075ad6df0bc730', '0x0f5a6411704c5ff8464305ef67088eee6471225fb1c26d1c1f2252c87c72aa10', '0x5792021e91c1f33abaca9f31c4a6aeb7e35fdd9085b20b9baa9a05cf73fc2abc', '0x63d45ae5924fce06d8735ceba1cc5af82500df91aa369fdd472c8117e85737da', '0x345ef96e951f98bccefff151681840726c5a00a6a6cacbd6993cff219d70ccf7', '0x347b3c2e5c39f66fdcccc09f257577cb541c2d93337f19cad9236eff670fd0b6', '0x200329d8869aa7e24387e7a6498ca8db5b9204131e599d781450c8f5dcb5bcc4', '0x46fb5e8c752a5f77d7f006822ecc4bf0959a47cd64ac2ff980b5b15ffc8c267c', '0x2b610b6d4573df14ff30bc6ab1eeecff2458618ed42ba5a1c5494b0a063279b5', '0x689c468194c384eb607cc43bf54d92390f344b5b1c0270f0807f5122272b9f5c', '0x19c3e3bef8ba3ccf9ce3afa8c766ac0defaa3f020aca5b906232b658be8c02ce', '0x27729e0dd67210cf2b25b9fc38309ca19e1d8434643c254b4d4530519f8780e3', '0x336229790e28c3ff900924523dea68b95d549dea83e6abe285e917a044fcd446', '0x0f2dc5640a3560c71777f1f9361b23d86d4ff723120ff12515917768b171aa29', '0x6932a9972927ff3f92543946712b30c85fd88b01d4345414418be334b2ba4af3', '0x72915ab6a8ec3f102639764a7a33d96964029bcb21780d921dc051be4a81f93b', '0x337b29a20510a082eddf2a664c3f751a02a1b64be87019f24c33a00c417e6934', '0x46f054fa58cbce40ab7d05992aa6d690daacfa26d531b5844f8d15e7c7199711', '0x1558bca327be73e696ba90d308d6af73d6ba3b60a412ef0c66cbef7fe25aefc5', '0x6d92913979d544c0c38b6251f967cc1b165e9e694214d948c82ae6a074cc0fa9', '0x3741da373085c27346b0801085781b614a54bd4bce4979a525806050792cfd85', '0x4c73aab1a70cec9bd6fa4e3dbaab917fdceeadc6452a40481494aa3a0ec3e0e2', '0x27646d6a85fd310d927c50e3ec5afc220cf8db2a4f6dd94ef5e590ee6d7a673d', '0x46fbb5e5008a603ede864bb1b540cd80aca27338ade25e0daa5b3e0e1ffe495d', '0x16861b90e41936606dd595bafadb6f1b615a83828ed9578f6363e2e55db49241', '0x62c10627bff16781a97f8e2bdff736db5d5b130a278ecd20dce7c8bd4f7774e8', '0x58fe05dc78efb0e0121fc0ad1fd968bcf712274d93e90c3a11fa4c73d62a0e79', '0x16def1d6454b6b95a9f4e7ecdc3b804d06335205b58d4eea5292f3eb29b27630', '0x0bf2632473bc139e104177b8bba4f42f34f19180fc3f731f1e06d2fcca485ecf', '0x5d408b3babaab3cb5b8c8e5941fc224eb27fdc53db801d1cfef863e0e5fe89a0', '0x407317cb9a9a4f51d292b9befde38e46e21a7f134bebb4c44699b19f7a164995', '0x45ba2e0aea07cc2dca14f2bc4f267c585023716fc2177d6eade85936e8295e99', '0x02edce6b996c6348e90ce3b39e21dc171814b410c8f97ffe58d8b8a1fd52a209', '0x075ca2016eebd050f6731e3455df65326b06f90d35e57ad627537d725bed99e7', '0x59a3bd67ca6d412f08fd7063711074c9fb4524ccc3b251e10acc13fef74bc1c1', '0x39a8b129db28d0102c3f0d8e5c5268f279079bab722fbb734b309119f52c56a7', '0x2d7c55f49238262cc59d66cebb3c61dfc4714b2652a80899f714f493c8e47e65', '0x08a53b3d7097bb5ba964a98a2782a1674b2e1d79602c9007bf95da0c693278a4', '0x6acd941495b63ed3fe212ecfc35c588332740401caa2e44f28210c202d8236e7', '0x4d11d0c9f9094891262a839f95fd2bdfab17a3f1344457dee6ff098e36a4c3a4', '0x355bdc00fadfbc92e46c07361d9345bedd2a27a067c8c7caafb330d97b02cd2c', '0x5fed17d72abf60f92b8632a3f7200283cf9c1741295059b9c68008ceabde00a4', '0x4cf1b0e36496d5befa25f24ac3e69f2cd34b79c9d2b677c4e45d639c98888f00', '0x5d83832a63337c066800caf0a54fda718219ca960ea36e57c9c8da9603cd1c64', '0x5c3ca6b96a146a3b0e5fd4810ade915147798d490be6ef565c0ff88445719a48', '0x6b94f00fc8644a90691b4884b2c017cf53b7cba20bab4ef412ef65eb80c0fef2', '0x2bb1f9653c2a884a0a9bb6b5ec152045cc9212a73b20a07bcfda7d5e1a571fed', '0x31043b837f552bdc27046de44875151072980ca74dff1709dcebd840e66f8a7b', '0x6fd21442936e67166bea8378c277d9eaa1d8a23a9e1fc75a8124a189c6fe05db', '0x5550ce346931f43d02f341a4d0f4c169c035c756947f659c26a44e38f0d16b35', '0x66cf04ffb8ee64e948f68675f04fb014175cf180bf06d5f287b7b5b76a4ac9c6', '0x3ea3684fe00c916ea4f297360d5d71d5914a8241f7e799b8d43837a75799e9f7', '0x0381b03d85261c8356386bdc140c182740ded340357ce6762224c02dfe332a04', '0x1736762a7ad020947b0099d319a464abee8ff66525e944e7eaae3e4a9e17d641', '0x0012327fa8efbb86f138a8025737437ed107e984c4efe288cad0fe5707be83d3', '0x1418e4c5a7b9bb66dcdad25b79b42687ecbf0e65a21f9c88d635d886e782793e', '0x256f44b96b0b582ff2d6c9667cf8ef5fe89336b696509aa70557583f91bfb898', '0x0b4a55ece046631e2c748fb620151ccfe71fe6fb7b6bf62d62c4e4c9d9e6f151', '0x19046a787e3c228c76e83d2ac1409d078d9c05816d4f7291400ba5dc9ccb1f88', '0x73c2a633e3be2422d881e2d7c91b5a407d70be4569c4de09b19bc21cb24a0115', '0x1d60e8c9db73e89d330903008312a6e10df634bf4615fa6b29a82d4d7097e12c', '0x3b2f06c77ab57b431919786a55c05d17fc540a55a5ee65596d01f9bd1b46c86c', '0x318cbc8fc1698f1fcae480ef4b18e767cffc69f0c571f9bf6453b312108160b0', '0x70f69a6250cbf19ae2e6d8a2c4ba47adf7de9ac94c8d3f1c1ff12d95a2fff0a0', '0x0c9650dc4d62f866b04059d237576ddc27ea684b59e997f5c003108659c0d7e5', '0x1d5544c0218a37121ffb8ec8719c93f826b7006bfb9abfc20e3ef78ba717b096', '0x2e743c833800188735b462f9b1da4b5c9a82c0b090838cb9c275e17b1bb51856', '0x6b9f4f8948359cea054eba85a66b6d01a3f43853542585e440ac9b53ef8e2e15', '0x5fb981893437b24931e3e8bf44e3d77ce5c2fa670d6c42208cba4d647b8dc754', '0x5b8f9e81d3840f1fb496f8f3481166b62d001ee4767d7212e7cd9923bf14b924', '0x514b86558a9d8341d6d52242273af87ef88b903d55ae95852a8791c10bbd1d79', '0x482da5ae1e2f0b81dd53d12277df485e2588c60aca052272acbe805930a5da32', '0x12c3a1c03baa37eba429a5a80a6b72160bd5f8839bb4ee12e1d94a7703c429dc', '0x6ed7d1fc9abebfd7db24de0fdeda4b2d4f2d0d69184b936621b9a8d09be9d0a2', '0x1a56f1e43c596c802db84169fd01dc9511243022261a18001a5e8333eacfeb96', '0x5e457c395c75c3ff09ab44592bff70930a9b840745225b9cb69f629a894f4e0b', '0x6e7f120e930ba8abd5e271a4338885c60a7511aaef01afea0bc1fdc4d48d4d79', '0x6dec9e9153b1b4ce9bd64e4c5cd16cb8c17634d70ed2de988e28b9e11bbe296f', '0x257108ad5fb1eb88bdcd1acbbab1a6254c19dca1e64b506c4c3ad21cee22d143', '0x3fb6750bb473ac6d077f4c9ef45a7b532399c05bbefc87d997c4d369e4095cf8', '0x652b5c409ed8c69cee74b158613a767e6bee589a0c0acc232a8c2b466c82e7cc', '0x2470eed5f58a3af4891eb5c65ed54ded32e877fc66135f56f6beb5c5cd2ac36d', '0x180b46226e75d5f6dc7b2704c2020980414d68b38cfaecec7728c245981fcdf5', '0x26c5773d85d0e05de8e55c724d413b39b38fc9687cd3a33f61e6284d41de6ed3', '0x2eb9cfb77d266f014b88a90e75896d7f038019df673cb7a277d34c3e3fa17eff', '0x1c48c9306add329daf89d0f09ed55b903d8c82e3fca6e84daa7410278af86d98', '0x53e8dc910c9ff8f41e29c7826d87fc3591bfc365c8f622ab57f920a63cd8b155', '0x117065a22405feebea2b25f5c6ff8feadafa0f94ba99b1c3cfc5dfe9280b8219', '0x70a02403e7518bbb49949b71652ffe21e55ca19004aab9b0b13ec0166ab42da4', '0x2a3176fcb7a7ac4ab39571b71693707ba1d3504314a66529c019895be8f0a3ce', '0x44150016991f7035254356ea30dc2b868b2868fe0daf7cd7ebe8e2a91cabb8a9', '0x3b0c7be21a559b906ede74566983fdc2e68e5b54c13058d46eef6108da488860', '0x421438710c49d163b1ae4bca529d18c99385a3dad450f438e22780b9d888b306', '0x175350c7a6856639f02656c3fffa28abd7ba69d9cf9539b4fdaddc491902523b', '0x5efd149402c32343294e224a20aa6b9189b6547236ce9784c6c5a7a5993fc8e8', '0x24b48d05697ce26d5b1a9ba388c3426421bdc731543cff90fa8f9bdfe9da075a', '0x0bc75d14d346c9093d625e3fac35fa6e8cc358b5741069824b0b878daf0d4c69', '0x37835f58255cf5ca3e9204c5b29d80f6004f65af0776c5750d2435f319794735', '0x08a8a35f99963376ef2c52ee67a4bd430d58420414248d4b18c86a6ab53d554f', '0x0c052cc4fea6bfc8cb12121666d7be070e62b3c191ca49f65cf866cf058dee7f', '0x0d1ce46d63e4b2ac76f5a3cc30ee164b53f916a8e616ee819fdc033c0557082a', '0x419ca18e6afd4f71c844bc55adf145fca5a49d8f5f59d44a2abde3a939cea030', '0x5dcd7bbf8826f7689c8b635ce21a2dbabb7543888987e2445338cf4edbf2be4d', '0x412b39974f462a151ab451501093ad51f0fe6ba8ea21fdc08c9e72712b95554d', '0x51f63e6cf0b5819f2104023ee2a04bf15e7eb2749c5bf4ae5535ee0eaed1102c', '0x363cbc93a6d0b29dbad98a622e9941d45f1d2158cbef42778ac2c76e63e722b3', '0x67d4eb6a54ac0335e7a78096a45881676f3e9611e8bf6b07ad05d8bd1b7043b5', '0x295e0e60f56f3b6f36d5382580bfff14d30bf0b069944f46832d6097be312fb9', '0x007a2d34847d833b74d0131ea56624edd451122e90e32cf9e249a827bb44f5f3', '0x581ed0f59a9f5f2d99745a9f623a0170eb42728b4c9bc66d772a309675ad5e3b', '0x05a80ff7418d0a4f2d900da7236dca37dbc610d53330b509bfe3d0624c6746ad', '0x2cc7aa05b074e84b46e21bfba06952761872a0efae4e46c79d4dd43396fc4f93', '0x185ef0d86e6febb95be7044d6d7f2f83c7015bd5bf400da59504fe568c44f4d2', '0x3c151467b58126a35f944d1e5e6b16c48fe21d4312ab6c0409cac51dee718169', '0x13545f3e11b1bfe65d4a40e45dc5d9ffeb3fe3f8290dd061a32fe554f0d47a9f', '0x2da7e740e1d97a21db174c470b1b8de4db7cb0a27d4fcde623331b5518fb2594', '0x149049829c3c540250c67aa57d8103d5a77c9b04cbac3b9a9163ee67a615b055', '0x445e332fa7da07d0b2bf42e1bfdabb2bf3ac1d242484da6f9ae6a2e4a46342d5', '0x1c0c2b971699135a03d282962bf67016072c0b785aea133f450a03a1dbf2b3f4', '0x429d349750a3ba851c67a22b508831a0381001bc48f0ef65f57519867002a684', '0x1d97d71829fcb83a50d0935caef73f4bc97c1613b0f249a80f9765ac8411011d', '0x7212161e73387f16b21ca3ddd1bc8c95185dbf4f2117b7ae9ed0288185f7edc1', '0x3c15bcb79543cbac591296c3310a1f1e0fc6f5fd66c9ec492166b0b83e5c361a', '0x49066cb2a7f9caa1bb1166734ffc151a39e7eb48c4d0c163b084fea81988c5a8', '0x11079aa2c6ba7eae2153c5c697e07865f266363024c6aa91e084336354b0da71', '0x15183bb514a28f276de73793b8d4b6d93baae7867894751f1eb4e8c0a5fd3a41', '0x4939eda79ae5c9b00b689ca003fe7897272c348efb697e4a17ae63f23ce3fd8c', '0x09b60d4571cb9a28fe8b2cc816afa42efc01fb4edb7d8a2aa0f301d22de974fb', '0x1f648aec8f4fb92f78b2545153d6c7b690ae0f7767b8787ed917eb496487bcfb', '0x4e8cfc91fd7ce2c3201839dbd859d4e3cb81716213058ba2e461031ca205a4f1', '0x50c9a4066e72296be3069020cea2b789430524e8126a0a37e9c75d1af4b1bf27', '0x23dd5c46fcf0265b5e093d506e6b65d30edcff859282a712014f8ad1dbc8f1e8', '0x50b58ded1c4f819c3c310bde44ff77e0e20d03bd6e3f19cb64e89fe76766258b', '0x01723af3c0f5e10a0bce51b5b43556b64c46ba0503326e3f1c23c88d889240cb', '0x583ffce9cfcd6ec12b51f73a7b2c003d745701d0341ef1dfa54e032242c00b46', '0x5054f3bdf252454f69f5b0ea83154e6291c73f9ec6afa10b79f303dae113bcb7', '0x3f1b46b107803954934733e048ba943e0a9e5edd861afda4cfec100740c46637', '0x6f23fce7490779753e5c594ab2e97e6a6efb37770f97b1032034bc4ae26aafe8', '0x3e2c8d473441e25c36716a67af9d334850691e3aed74fea255483ef11ca6b888']
MDS_matrix = [['0x4d491a377113a8daccd13ab0066be558e27e6d5755543d54aaaaaaaa00000001', '0x56f23d7e5f361df6266b620607396203fece3b023ffec4ff3fffffff40000001', '0x458e97984c2b4b2b51ef819e6c2de803323e959b66656a65cccccccc33333334'],['0x56f23d7e5f361df6266b620607396203fece3b023ffec4ff3fffffff40000001', '0x458e97984c2b4b2b51ef819e6c2de803323e959b66656a65cccccccc33333334', '0x609b60c54d5893118005895c0806deaf1b1e08ad2aa94ca9d555555480000001'],['0x458e97984c2b4b2b51ef819e6c2de803323e959b66656a65cccccccc33333334', '0x609b60c54d5893118005895c0806deaf1b1e08ad2aa94ca9d555555480000001', '0x211f5460e751918257c7624b7077624aaa362edc49241a48db6db6db24924925']]
MDS_matrix_field = matrix(F, t, t)
for i in range(0, t):
    for j in range(0, t):
        MDS_matrix_field[i, j] = F(int(MDS_matrix[i][j], 16))
round_constants_field = []
for i in range(0, (R_F + R_P) * t):
    round_constants_field.append(F(int(round_constants[i], 16)))

def print_words_to_hex(words):
    hex_length = int(ceil(float(n) / 4)) + 2 # +2 for "0x"
    print(["{0:#0{1}x}".format(int(entry), hex_length) for entry in words])

def print_words_to_ark_ff(words):
    print("[")
    print(",\n".join(["field_new!(Fr,\"{}\")".format(int(entry)) for entry in words]))
    print("]")

def write_words_to_ark_ff(words):
    vec_string = "vec![" + ",".join(["Fp(field_new!(Fr, \"{}\"))".format(int(entry)) for entry in words]) + "]"
    file = open('width3','w')
    file.write(vec_string)

def print_concat_words_to_large(words):
    hex_length = int(ceil(float(n) / 4))
    nums = ["{0:0{1}x}".format(int(entry), hex_length) for entry in words]
    final_string = "0x" + ''.join(nums)
    print(final_string)

def perm(input_words):
    R_f = int(R_F / 2)
    round_constants_counter = 0
    state_words = list(input_words)
    # First full rounds
    for r in range(0, R_f):
        # Round constants, nonlinear layer, matrix multiplication
        for i in range(0, t):
            state_words[i] = state_words[i] + round_constants_field[round_constants_counter]
            round_constants_counter += 1
        for i in range(0, t):
            state_words[i] = (state_words[i])^5
        state_words = list(MDS_matrix_field * vector(state_words))
    # Middle partial rounds
    for r in range(0, R_P):
        # Round constants, nonlinear layer, matrix multiplication
        for i in range(0, t):
            state_words[i] = state_words[i] + round_constants_field[round_constants_counter]
            round_constants_counter += 1
        state_words[0] = (state_words[0])^5
        state_words = list(MDS_matrix_field * vector(state_words))
    # Last full rounds
    for r in range(0, R_f):
        # Round constants, nonlinear layer, matrix multiplication
        for i in range(0, t):
            state_words[i] = state_words[i] + round_constants_field[round_constants_counter]
            round_constants_counter += 1
        for i in range(0, t):
            state_words[i] = (state_words[i])^5
        state_words = list(MDS_matrix_field * vector(state_words))
    return state_words

domain_tag = F((1 << arity) - 1)
input_words = [domain_tag, F(1), F(2)]
output_words = perm(input_words)

print("Input:")
print_words_to_hex(input_words)
print("Output:")
print_words_to_ark_ff(output_words)
write_words_to_ark_ff(output_words)
