"""
Task corpus for the Enigma Decrypt environment.

60 realistic WWII German military messages across 5 categories:
- Weather reports (WETTER)
- U-boat reports (UBOOT)
- Operational orders (BEFEHL)
- Status reports (LAGEBERICHT)
- Miscellaneous (MISC)

Each task is encrypted with specific Enigma settings and includes
difficulty-appropriate cribs and revealed information.

Message conventions:
- Uppercase A-Z only
- X = period/stop
- ZZ = comma
- Q replaces CH (e.g., NICHT -> NIQT)
- Numbers spelled out in German
"""

import json
import random
from pathlib import Path
from enigma_machine import EnigmaMachine

# ---------------------------------------------------------------------------
# Message corpus: realistic WWII German military messages
# ---------------------------------------------------------------------------

MESSAGES = [
    # --- WEATHER REPORTS (12) ---
    {
        "id": "wetter_001",
        "category": "WETTER",
        "plaintext": "WETTERBERIQTXWINDSTAERKEDREIAUSNORDWESTXBEWOELKTXSIQTUNTERFUENFKILOMETERX",
        "intercept": {"time": "0607", "date": "14.3.43", "frequency": "4715 kc/s", "callsign_from": "DAN", "callsign_to": "KLD", "network": "Red"},
    },
    {
        "id": "wetter_002",
        "category": "WETTER",
        "plaintext": "WETTERVORHERSAGEXLEIQTERREGENVONWESTENERWARTETZZMITTAGSAUFKLARUNGMOEGLIX",
        "intercept": {"time": "0531", "date": "22.11.42", "frequency": "6790 kc/s", "callsign_from": "RTW", "callsign_to": "FJK", "network": "Red"},
    },
    {
        "id": "wetter_003",
        "category": "WETTER",
        "plaintext": "WETTERLAGENORDSEEXWINDSTAERKEFUENFAUSNORDXWELLENHOEHEDREIBISVIERMETERZZSIQTGUTX",
        "intercept": {"time": "0715", "date": "3.9.42", "frequency": "8540 kc/s", "callsign_from": "MQR", "callsign_to": "BDU", "network": "Dolphin"},
    },
    {
        "id": "wetter_004",
        "category": "WETTER",
        "plaintext": "WETTERMELDUNGXTEMPERATURZWOELFGRADXLUFTDRUQEINSTAUSENDUNDZWANZIGMILLIBARXNEBELBISZEHNUHRX",
        "intercept": {"time": "0622", "date": "7.1.44", "frequency": "3925 kc/s", "callsign_from": "PKE", "callsign_to": "WLG", "network": "Red"},
    },
    {
        "id": "wetter_005",
        "category": "WETTER",
        "plaintext": "WETTERBERIQTFUERSTATIONBREMENXBEDEQTXNIESELREGENXSIQTUNTEREINSKOMMAZWEIKILOMETERX",
        "intercept": {"time": "0645", "date": "19.10.43", "frequency": "4715 kc/s", "callsign_from": "HVN", "callsign_to": "KLD", "network": "Red"},
    },
    {
        "id": "wetter_006",
        "category": "WETTER",
        "plaintext": "SEEWETTERBERIQTXWINDNORDOSTZZSEEGANGLEIQQXSIQTGUTXFUENFSEEMEILENXBAROMETERSTEIGENDX",
        "intercept": {"time": "1204", "date": "28.6.43", "frequency": "10230 kc/s", "callsign_from": "VJW", "callsign_to": "BDU", "network": "Shark"},
    },
    {
        "id": "wetter_007",
        "category": "WETTER",
        "plaintext": "WETTERLAGEOSTFRONTXSTARKERFROSTERWARTETZZTEMPERATURBISMINUSZWANZIGGRADUNTERX",
        "intercept": {"time": "0558", "date": "12.12.42", "frequency": "5810 kc/s", "callsign_from": "QNA", "callsign_to": "AGK", "network": "Orange"},
    },
    {
        "id": "wetter_008",
        "category": "WETTER",
        "plaintext": "WETTERVORHERSAGEFUERMITTELMEERSEKTORXAUFKLARUNGZZTEMPERATURDREIUNDZWANZIGGRADUNDWAERMX",
        "intercept": {"time": "0630", "date": "15.7.43", "frequency": "7225 kc/s", "callsign_from": "TKF", "callsign_to": "NLB", "network": "Light Blue"},
    },
    {
        "id": "wetter_009",
        "category": "WETTER",
        "plaintext": "MORGENWETTERBERIQTXWOLKENUNTERGRENZEFUENFHUNDERTMETERXLEIQQTERSCHNEEFALLSEITDREIUHRX",
        "intercept": {"time": "0503", "date": "2.2.43", "frequency": "5810 kc/s", "callsign_from": "GBR", "callsign_to": "AGK", "network": "Orange"},
    },
    {
        "id": "wetter_010",
        "category": "WETTER",
        "plaintext": "NAQTWITTERUNGSBERIQTXKLAREHIMMELXMONDLIQTGUTXSIQTWEITERDREISSIGKILOMETERX",
        "intercept": {"time": "2215", "date": "8.5.44", "frequency": "4715 kc/s", "callsign_from": "SDF", "callsign_to": "FJK", "network": "Red"},
    },
    {
        "id": "wetter_011",
        "category": "WETTER",
        "plaintext": "WETTERWARNUNGXSTARKERGEWITTERVONSUEDWESTENIMANZUGXALLEFLUGOPERATIONENEINSTELLENX",
        "intercept": {"time": "1347", "date": "21.8.43", "frequency": "6790 kc/s", "callsign_from": "KLD", "callsign_to": "ALL", "network": "Red"},
    },
    {
        "id": "wetter_012",
        "category": "WETTER",
        "plaintext": "WETTERBERIQTATLANTIKXWINDSTAERKESIEBENZZSEEGANGRAUQXSIQTUNTERZWEISEEMEILENX",
        "intercept": {"time": "0932", "date": "5.4.43", "frequency": "10230 kc/s", "callsign_from": "NWE", "callsign_to": "BDU", "network": "Shark"},
    },

    # --- U-BOAT REPORTS (12) ---
    {
        "id": "uboot_001",
        "category": "UBOOT",
        "plaintext": "ANBEFEHLSHABERDERVBOOTEXKEINEFEINDBERUERUNGXQUADRATAQTDREINEUNSIEBENXKURSSUEDSUESTWESXFAHRTAQTKNOTEN",
        "intercept": {"time": "1423", "date": "17.3.43", "frequency": "10230 kc/s", "callsign_from": "UDK", "callsign_to": "BDU", "network": "Shark"},
    },
    {
        "id": "uboot_002",
        "category": "UBOOT",
        "plaintext": "GELEITZUGGESIQTETXQUADRATBERTAVIERFUENFXKURSOSTNORDOSTXGESQAETZTZWANZIGFAQRZEUGEX",
        "intercept": {"time": "0847", "date": "11.5.43", "frequency": "10230 kc/s", "callsign_from": "VEH", "callsign_to": "BDU", "network": "Shark"},
    },
    {
        "id": "uboot_003",
        "category": "UBOOT",
        "plaintext": "TORPEDOANGRIFFXZWEITREFFERAUFDREITAUSENDTONNERXSIQVERSTEXMANNAQAFTWOHLAUFX",
        "intercept": {"time": "0312", "date": "9.2.43", "frequency": "8540 kc/s", "callsign_from": "RKM", "callsign_to": "BDU", "network": "Shark"},
    },
    {
        "id": "uboot_004",
        "category": "UBOOT",
        "plaintext": "BRENNSTOFFVORRATNURNOXFUERFUENFTAGEREICHENDXERBITTEDRINGENDVERSORGUNGSTREFFENX",
        "intercept": {"time": "1609", "date": "24.6.43", "frequency": "10230 kc/s", "callsign_from": "PLN", "callsign_to": "BDU", "network": "Shark"},
    },
    {
        "id": "uboot_005",
        "category": "UBOOT",
        "plaintext": "MUSSTAUQENWEGENFEINDLIQERORTUNGXWASSERBOMBENANGRIFFDREISTUNDENXKEINESCHAEDENX",
        "intercept": {"time": "1745", "date": "30.7.43", "frequency": "8540 kc/s", "callsign_from": "JFS", "callsign_to": "BDU", "network": "Shark"},
    },
    {
        "id": "uboot_006",
        "category": "UBOOT",
        "plaintext": "RUFZEIQLANGXVBOOTVIERDREIAQTVONKIELAUSGELAUFENXZIELQUADRATDORAVIERSIEBENZWEIX",
        "intercept": {"time": "1600", "date": "1.4.43", "frequency": "8540 kc/s", "callsign_from": "WKL", "callsign_to": "BDU", "network": "Dolphin"},
    },
    {
        "id": "uboot_007",
        "category": "UBOOT",
        "plaintext": "GELEITDIENSTFUERVBOOTREMUSXABFAHRTWAERNEMUENDEXSEXZEHNUHRXMITSIEBENWEITERENVBOOTEN",
        "intercept": {"time": "1345", "date": "2.5.45", "frequency": "8540 kc/s", "callsign_from": "BDU", "callsign_to": "NWE", "network": "Dolphin"},
    },
    {
        "id": "uboot_008",
        "category": "UBOOT",
        "plaintext": "FEINDLIQERZERSOERERGESIQTETXQUADRATADASECHSEINSXHOEQSTEGESCHWINDIGKEITFAHRENX",
        "intercept": {"time": "2231", "date": "18.9.42", "frequency": "10230 kc/s", "callsign_from": "FBG", "callsign_to": "BDU", "network": "Shark"},
    },
    {
        "id": "uboot_009",
        "category": "UBOOT",
        "plaintext": "WETTERKURZSIGNALXLUFTDRUQNEUNSIEBENNEUNMILLIBARXWINDWESTFUENFXSEEGANGLEIQQX",
        "intercept": {"time": "0600", "date": "23.3.43", "frequency": "10230 kc/s", "callsign_from": "UDK", "callsign_to": "BDU", "network": "Shark"},
    },
    {
        "id": "uboot_010",
        "category": "UBOOT",
        "plaintext": "ERFOLGSBERIQTXZWEIHANDELSSCHIFFEVERSENKTXGESAMTZWOELFEINHALBTAUSENDTONNENX",
        "intercept": {"time": "0415", "date": "14.11.42", "frequency": "8540 kc/s", "callsign_from": "HQT", "callsign_to": "BDU", "network": "Shark"},
    },
    {
        "id": "uboot_011",
        "category": "UBOOT",
        "plaintext": "VONBEFEHLSHABERDERUBOOTEANALLEVBOOTEATLANTIKXNEUEOPERATIONSZONEQUADRATEDORAFINKENX",
        "intercept": {"time": "0800", "date": "6.1.43", "frequency": "10230 kc/s", "callsign_from": "BDU", "callsign_to": "ALL", "network": "Shark"},
    },
    {
        "id": "uboot_012",
        "category": "UBOOT",
        "plaintext": "VBOOTSEQSEINSNULLXSQWERBESQAEDIGTXRUEKFAHRTNAQBRESTXERBITTEGELEITSQUTZX",
        "intercept": {"time": "1122", "date": "9.8.43", "frequency": "8540 kc/s", "callsign_from": "TMR", "callsign_to": "BDU", "network": "Shark"},
    },

    # --- OPERATIONAL ORDERS (12) ---
    {
        "id": "befehl_001",
        "category": "BEFEHL",
        "plaintext": "BEFEHLNUMMERDREIVIERSIEBENXALLEEINHEITENVORRUEQKENRIQTUNGNORDOSTXBEREITAQAFTBISNEUNZEHNUHRDREISSIGX",
        "intercept": {"time": "0430", "date": "22.6.41", "frequency": "5810 kc/s", "callsign_from": "AGN", "callsign_to": "DIV", "network": "Orange"},
    },
    {
        "id": "befehl_002",
        "category": "BEFEHL",
        "plaintext": "ANGRIFFAUFLINIEALFABERTAZWEINULLDREIUHRXSQWERARTILLERIEVORBEREITUNGABEINSAQTZEHNUHRX",
        "intercept": {"time": "2045", "date": "4.7.43", "frequency": "5810 kc/s", "callsign_from": "KPS", "callsign_to": "RGT", "network": "Orange"},
    },
    {
        "id": "befehl_003",
        "category": "BEFEHL",
        "plaintext": "SOFORTIGERABRUQNAQWESTENXFEINDLIQEDURQBRUQSSTELLUNGCAESARXALLEEINHEITENZURUEKNEHMEX",
        "intercept": {"time": "1415", "date": "12.8.44", "frequency": "3925 kc/s", "callsign_from": "AGW", "callsign_to": "KPS", "network": "Yellow"},
    },
    {
        "id": "befehl_004",
        "category": "BEFEHL",
        "plaintext": "FUENFTEPANZERDIVISIONVERLEGTNAQSEKTORSUEDXANKUNFTERWARTETSIEBENUHRDREISSIGX",
        "intercept": {"time": "1830", "date": "15.3.43", "frequency": "5810 kc/s", "callsign_from": "AGS", "callsign_to": "PZD", "network": "Orange"},
    },
    {
        "id": "befehl_005",
        "category": "BEFEHL",
        "plaintext": "FLIEGERKOPSZWEIXALLEBOMBERGRUPPENSTARTENZIELHAFENANLAGENXNULLDREIHUNDERTXHOEQSTEALARMSTUFE",
        "intercept": {"time": "0215", "date": "29.4.43", "frequency": "6790 kc/s", "callsign_from": "FKZ", "callsign_to": "BOM", "network": "Red"},
    },
    {
        "id": "befehl_006",
        "category": "BEFEHL",
        "plaintext": "VERTEIDIGUNGSBEFEHLXHAUPTSTELLUNGISTUMJEDENPREISZUHALTENXKEINWEITERERRUQZUGX",
        "intercept": {"time": "0930", "date": "20.1.45", "frequency": "3925 kc/s", "callsign_from": "AGM", "callsign_to": "DIV", "network": "Yellow"},
    },
    {
        "id": "befehl_007",
        "category": "BEFEHL",
        "plaintext": "AUFKLAERUNGSBEFEHLXDRITTEKOMPANIEERKUNDETSTRASSENNAQNORDENXERGEBNISMELDENBISVIERZEHNUHR",
        "intercept": {"time": "0545", "date": "3.11.42", "frequency": "5810 kc/s", "callsign_from": "RGT", "callsign_to": "KMP", "network": "Orange"},
    },
    {
        "id": "befehl_008",
        "category": "BEFEHL",
        "plaintext": "PIONIERKOMPANIESOLLBRUEQEUEBERFLUSSSPREEHERSTELLENXFERTIGSTELLUNGBISHEUDNAQTX",
        "intercept": {"time": "1100", "date": "25.4.45", "frequency": "3925 kc/s", "callsign_from": "PIB", "callsign_to": "KMP", "network": "Yellow"},
    },
    {
        "id": "befehl_009",
        "category": "BEFEHL",
        "plaintext": "NEUEKOMANDOSTRUKTURXOBERSTVONSTEINNXUEBERNIMMTFUEHRUNGDERABSQNITTSNORDX",
        "intercept": {"time": "0800", "date": "7.9.44", "frequency": "5810 kc/s", "callsign_from": "AGN", "callsign_to": "ABN", "network": "Orange"},
    },
    {
        "id": "befehl_010",
        "category": "BEFEHL",
        "plaintext": "ALLENAQRIQTENEINHEITENXFUNKSTILLEXNURNOTFUNKVONNULLEINSUHRBISMITTTERNAQTX",
        "intercept": {"time": "2300", "date": "5.6.44", "frequency": "3925 kc/s", "callsign_from": "AGW", "callsign_to": "ALL", "network": "Yellow"},
    },
    {
        "id": "befehl_011",
        "category": "BEFEHL",
        "plaintext": "GEHEIMXOBERESKOMMANDODERWEQRMAQTXOPERATIONSPLANFAELLTWINTERXAUSFUEHRUNGAMDRITTENDEZEMBERX",
        "intercept": {"time": "1400", "date": "10.12.44", "frequency": "3280 kc/s", "callsign_from": "OKW", "callsign_to": "AGW", "network": "Yellow"},
    },
    {
        "id": "befehl_012",
        "category": "BEFEHL",
        "plaintext": "NAQRIQTENVERBINDUNGNAQSEKTOROSTUNTERBROQENXFUNKVERBINDUNGWIEDERHERSTELLENPRIORX",
        "intercept": {"time": "0915", "date": "28.2.43", "frequency": "5810 kc/s", "callsign_from": "NAQ", "callsign_to": "SIG", "network": "Orange"},
    },

    # --- STATUS REPORTS (12) ---
    {
        "id": "lage_001",
        "category": "LAGEBERICHT",
        "plaintext": "LAGEBERIQTXMUNITIONSVORRATGUTXVERPFLEGUNGFUERFUENFTAGEGESIQERTXPERSONALSTAERKEDREIHUNDERTFUENFX",
        "intercept": {"time": "1800", "date": "19.11.42", "frequency": "5810 kc/s", "callsign_from": "BTL", "callsign_to": "RGT", "network": "Orange"},
    },
    {
        "id": "lage_002",
        "category": "LAGEBERICHT",
        "plaintext": "KEINEBESONDERENEREIGNISSEZUMELDENZZMELDUNGABGESQLOSSENXHEILHITLERX",
        "intercept": {"time": "1805", "date": "14.4.42", "frequency": "5810 kc/s", "callsign_from": "FPR", "callsign_to": "AGN", "network": "Orange"},
    },
    {
        "id": "lage_003",
        "category": "LAGEBERICHT",
        "plaintext": "TAEGLIQERBERIQTXFEINDLIQEAKTIVITAETGERINGXEIGENESTELLUNGENUNVERAENDERTGEHALTEX",
        "intercept": {"time": "1810", "date": "6.3.43", "frequency": "5810 kc/s", "callsign_from": "DIV", "callsign_to": "KPS", "network": "Orange"},
    },
    {
        "id": "lage_004",
        "category": "LAGEBERICHT",
        "plaintext": "VERLUSTMELDUNGXDREITOTEZWANZIGVERWUNDETESIEBENVERMISSXSQWEREVERLUSTEINDRITTERKOMPANIEX",
        "intercept": {"time": "2030", "date": "18.7.43", "frequency": "5810 kc/s", "callsign_from": "RGT", "callsign_to": "DIV", "network": "Orange"},
    },
    {
        "id": "lage_005",
        "category": "LAGEBERICHT",
        "plaintext": "VERSORGUNGSLAGEKRITISQXBRENNSTOFFVORRATNURFUERZWEITAGEXDRINGENDNAQSQUBERFOERDERNX",
        "intercept": {"time": "0700", "date": "23.1.43", "frequency": "5810 kc/s", "callsign_from": "QMT", "callsign_to": "AGS", "network": "Orange"},
    },
    {
        "id": "lage_006",
        "category": "LAGEBERICHT",
        "plaintext": "PANZERSTAERKEBEREIQTXVIERZEHNPANZERKAMPFWAGENEINSNOXEINSATZBEREITXAQUZERSOERERAUSGEFALLX",
        "intercept": {"time": "0830", "date": "10.8.43", "frequency": "5810 kc/s", "callsign_from": "PZR", "callsign_to": "PZD", "network": "Orange"},
    },
    {
        "id": "lage_007",
        "category": "LAGEBERICHT",
        "plaintext": "TAETIGKEITSBERIQTLUFTFLOTTEZWEIXEINSAETZEZWEIUNDVIERZIGFLIEGERSTAFFELNHEUTEX",
        "intercept": {"time": "2100", "date": "1.9.43", "frequency": "6790 kc/s", "callsign_from": "LF2", "callsign_to": "RLM", "network": "Red"},
    },
    {
        "id": "lage_008",
        "category": "LAGEBERICHT",
        "plaintext": "FEINDLAGEBERIQTXFEINDVERSTAERKTSTELLUNGENMITPANZERNUNDINAFNTERIEXANGRIFFERWARTEX",
        "intercept": {"time": "1445", "date": "5.7.43", "frequency": "5810 kc/s", "callsign_from": "NAQ", "callsign_to": "AGS", "network": "Orange"},
    },
    {
        "id": "lage_009",
        "category": "LAGEBERICHT",
        "plaintext": "BEFESTIGUNGSARBEITENAMHAUPTSTELLUNGABGESQLSSENXDRAHTHINDERNISSEUNDMINENFELDERVOLLSTAENDG",
        "intercept": {"time": "1700", "date": "27.10.43", "frequency": "5810 kc/s", "callsign_from": "PIB", "callsign_to": "DIV", "network": "Orange"},
    },
    {
        "id": "lage_010",
        "category": "LAGEBERICHT",
        "plaintext": "NAQRIQTENMELDUNGXFEINDLIQERFUNKVERKEHRSTARKANGESTIEGENXMOEGLIQUERWEISEANGRIFFSGRUPPENX",
        "intercept": {"time": "2245", "date": "4.6.44", "frequency": "3925 kc/s", "callsign_from": "SIG", "callsign_to": "AGW", "network": "Yellow"},
    },
    {
        "id": "lage_011",
        "category": "LAGEBERICHT",
        "plaintext": "SANITAETSBERIQTXKRANKENSTANDEINSZWOSIEBENGEINXEPIDEMIEUNTERKONTROXLAZARETTAUSGELASTETX",
        "intercept": {"time": "0900", "date": "16.12.42", "frequency": "5810 kc/s", "callsign_from": "SAN", "callsign_to": "DIV", "network": "Orange"},
    },
    {
        "id": "lage_012",
        "category": "LAGEBERICHT",
        "plaintext": "GEFEQTSBERIQTXFEINDLIQERANGRIFFABGEWIESENXEIGENEVERLUSTEGERINGXSTELLUNGENGEHALTEX",
        "intercept": {"time": "0315", "date": "13.2.43", "frequency": "5810 kc/s", "callsign_from": "BTL", "callsign_to": "RGT", "network": "Orange"},
    },

    # --- MISCELLANEOUS (12) ---
    {
        "id": "misc_001",
        "category": "MISC",
        "plaintext": "ANERKENUNGANDIEMAQNNSCHAFTENFUERTAPFEREXVERTEIDIGUNGAMBRUEQKENKOPFXHEILHITLERX",
        "intercept": {"time": "1200", "date": "30.8.43", "frequency": "5810 kc/s", "callsign_from": "AGS", "callsign_to": "BTL", "network": "Orange"},
    },
    {
        "id": "misc_002",
        "category": "MISC",
        "plaintext": "AGENTMELDETFEINDLIQETRUPPENBEWEGUNGENSUELIQQVONPARISINRIQTUNGDIJONXSTAERKEUBEKANTX",
        "intercept": {"time": "0345", "date": "12.6.44", "frequency": "3280 kc/s", "callsign_from": "ABW", "callsign_to": "OKW", "network": "Yellow"},
    },
    {
        "id": "misc_003",
        "category": "MISC",
        "plaintext": "TESTFUNKMELDUNGXFUNKANLAGEGEPRUEFTUNDBEREITXSENDEQUALITAETGUTXEMPFANGKLARX",
        "intercept": {"time": "0755", "date": "1.1.43", "frequency": "4715 kc/s", "callsign_from": "SIG", "callsign_to": "SIG", "network": "Red"},
    },
    {
        "id": "misc_004",
        "category": "MISC",
        "plaintext": "URLAUBSANTRAGEGENEHMIGTFUEROFFIZIEREVONDERDRITTENBRIGADEXABREISEAMSIEBTENX",
        "intercept": {"time": "1030", "date": "4.3.44", "frequency": "5810 kc/s", "callsign_from": "BRG", "callsign_to": "PER", "network": "Orange"},
    },
    {
        "id": "misc_005",
        "category": "MISC",
        "plaintext": "NAQSQUBLIEFERUNGXZWOELFWAGENLADUNGENMUNITIONERREIQENVORRATSLAGERSIEBENHUNERTTX",
        "intercept": {"time": "1415", "date": "20.5.43", "frequency": "5810 kc/s", "callsign_from": "QMT", "callsign_to": "VRL", "network": "Orange"},
    },
    {
        "id": "misc_006",
        "category": "MISC",
        "plaintext": "EINSSIEBENDREINULLVBOOTXERGIBTSIQDEMFEINDNIQTXSIEGEODERTODXHEILHITLERX",
        "intercept": {"time": "1930", "date": "5.5.45", "frequency": "8540 kc/s", "callsign_from": "UDK", "callsign_to": "BDU", "network": "Shark"},
    },
    {
        "id": "misc_007",
        "category": "MISC",
        "plaintext": "ABFANGMELDEUNGXFEINDLIQEBOMBERVERBAENDEIMANZUGAQSEVOMWESTENXALLEJAEGERSTAFFELNSTARTX",
        "intercept": {"time": "1342", "date": "17.8.43", "frequency": "4715 kc/s", "callsign_from": "JFC", "callsign_to": "ALL", "network": "Red"},
    },
    {
        "id": "misc_008",
        "category": "MISC",
        "plaintext": "GEHEIMHALTUNGSSTUFEXXSTRENGGEHEIMXXNURFUERFUEHRUNGSOFFIZIEREXKEINEFUNKUEBERTRAGUNGX",
        "intercept": {"time": "0900", "date": "11.12.44", "frequency": "3280 kc/s", "callsign_from": "OKW", "callsign_to": "AGW", "network": "Yellow"},
    },
    {
        "id": "misc_009",
        "category": "MISC",
        "plaintext": "KRIEGSTAGEBAQEINTRAGXHEUTIGERDATENULLAQTMAERZVIERUNDVIERZIGXLAGEUNVERAENDERTX",
        "intercept": {"time": "2350", "date": "8.3.44", "frequency": "5810 kc/s", "callsign_from": "DIV", "callsign_to": "KPS", "network": "Orange"},
    },
    {
        "id": "misc_010",
        "category": "MISC",
        "plaintext": "MELDUNGFUERGENERALSTABDESEERESXFEINDLIQEPANZERVERBAENDEDUQBRUQBEIKURSXZWEITEDIVISIONXXX",
        "intercept": {"time": "0420", "date": "20.7.43", "frequency": "5810 kc/s", "callsign_from": "NAQ", "callsign_to": "OKH", "network": "Orange"},
    },
    {
        "id": "misc_011",
        "category": "MISC",
        "plaintext": "EISENBAHNVERSORGUNGXNAQSQUBTRANSPORTUEBERSTUTTGARTHAUPBAHNHOFNAQDRESDENXANKUNFTMORGENX",
        "intercept": {"time": "1545", "date": "9.10.44", "frequency": "3925 kc/s", "callsign_from": "TRN", "callsign_to": "QMT", "network": "Yellow"},
    },
    {
        "id": "misc_012",
        "category": "MISC",
        "plaintext": "SONDERMELDUNGXDERADLERHORSTISTEINGENNOMENXZIELDESANGRIFFSSERREIQTXHEIMKEHRENDEX",
        "intercept": {"time": "1630", "date": "4.5.45", "frequency": "3925 kc/s", "callsign_from": "DIV", "callsign_to": "KPS", "network": "Yellow"},
    },
]


# ---------------------------------------------------------------------------
# Machine configurations per difficulty tier
# ---------------------------------------------------------------------------

def _generate_settings(difficulty: str, rng: random.Random) -> dict:
    """Generate Enigma machine settings appropriate for difficulty tier."""
    rotors = ["I", "II", "III", "IV", "V"]
    reflectors = ["UKW-A", "UKW-B", "UKW-C"]

    # Select 3 random rotors (no duplicates)
    rotor_order = rng.sample(rotors, 3)
    reflector = rng.choice(reflectors)

    # Ring settings: 1-26
    ring_settings = [rng.randint(1, 26) for _ in range(3)]

    # Initial positions: 1-26
    initial_positions = [rng.randint(1, 26) for _ in range(3)]

    # Plugboard pairs
    if difficulty == "easy":
        num_pairs = rng.randint(6, 10)
    elif difficulty == "medium":
        num_pairs = rng.randint(3, 5)
    else:  # hard
        num_pairs = rng.randint(2, 3)

    available = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    rng.shuffle(available)
    plugboard = []
    for i in range(0, num_pairs * 2, 2):
        if i + 1 < len(available):
            plugboard.append((available[i], available[i + 1]))

    return {
        "rotor_order": rotor_order,
        "ring_settings": ring_settings,
        "initial_positions": initial_positions,
        "reflector": reflector,
        "plugboard": plugboard,
    }


def _generate_cribs(plaintext: str, difficulty: str, rng: random.Random) -> list[dict]:
    """Generate known-plaintext cribs from a message."""
    cribs = []
    msg_len = len(plaintext)

    if difficulty == "easy":
        # 1-2 short cribs
        num_cribs = rng.randint(1, 2)
        crib_len_range = (4, 8)
    elif difficulty == "medium":
        # 2-3 medium cribs
        num_cribs = rng.randint(2, 3)
        crib_len_range = (5, 12)
    else:  # hard
        # 3-4 longer cribs
        num_cribs = rng.randint(3, 4)
        crib_len_range = (6, 15)

    used_ranges = []
    for _ in range(num_cribs):
        crib_len = rng.randint(*crib_len_range)
        crib_len = min(crib_len, msg_len - 1)

        # Try to find a non-overlapping position
        for _attempt in range(50):
            pos = rng.randint(0, msg_len - crib_len)
            # Check no overlap with existing cribs
            overlap = False
            for start, end in used_ranges:
                if not (pos + crib_len <= start or pos >= end):
                    overlap = True
                    break
            if not overlap:
                crib_text = plaintext[pos:pos + crib_len]
                cribs.append({"text": crib_text, "position": pos})
                used_ranges.append((pos, pos + crib_len))
                break

    return cribs


def _revealed_info(settings: dict, difficulty: str) -> dict:
    """Determine what machine settings to reveal based on difficulty."""
    if difficulty == "easy":
        # Reveal everything except initial positions
        return {
            "rotor_order": settings["rotor_order"],
            "ring_settings": settings["ring_settings"],
            "reflector": settings["reflector"],
            "plugboard": [list(p) for p in settings["plugboard"]],
            "hidden": ["initial_positions"],
        }
    elif difficulty == "medium":
        # Reveal rotor order and reflector only
        return {
            "rotor_order": settings["rotor_order"],
            "reflector": settings["reflector"],
            "num_plugboard_pairs": len(settings["plugboard"]),
            "hidden": ["ring_settings", "initial_positions", "plugboard"],
        }
    else:  # hard
        # Reveal only reflector (or choice of 2)
        return {
            "reflector": settings["reflector"],
            "num_plugboard_pairs": len(settings["plugboard"]),
            "hidden": ["rotor_order", "ring_settings", "initial_positions", "plugboard"],
        }


# ---------------------------------------------------------------------------
# Build all tasks
# ---------------------------------------------------------------------------

def build_all_tasks() -> dict[str, dict]:
    """Build and encrypt all tasks, returning a dict keyed by task ID."""
    # Deterministic RNG for reproducibility
    rng = random.Random(42)

    # Assign splits and difficulties
    # train: 15 easy, 15 medium, 10 hard = 40 tasks
    # test:  5 easy, 10 medium, 5 hard = 20 tasks
    assignments = []

    # Shuffle messages
    msg_indices = list(range(len(MESSAGES)))
    rng.shuffle(msg_indices)

    # Assign difficulties and splits
    train_easy = msg_indices[:15]
    train_medium = msg_indices[15:30]
    train_hard = msg_indices[30:40]
    test_easy = msg_indices[40:45]
    test_medium = msg_indices[45:55]
    test_hard = msg_indices[55:60]

    plan = []
    for idx in train_easy:
        plan.append((idx, "train", "easy"))
    for idx in train_medium:
        plan.append((idx, "train", "medium"))
    for idx in train_hard:
        plan.append((idx, "train", "hard"))
    for idx in test_easy:
        plan.append((idx, "test", "easy"))
    for idx in test_medium:
        plan.append((idx, "test", "medium"))
    for idx in test_hard:
        plan.append((idx, "test", "hard"))

    tasks = {}
    for msg_idx, split, difficulty in plan:
        msg = MESSAGES[msg_idx]
        task_id = f"{msg['id']}_{difficulty}"

        # Generate machine settings
        settings = _generate_settings(difficulty, rng)

        # Encrypt the plaintext
        machine = EnigmaMachine(
            rotor_order=settings["rotor_order"],
            ring_settings=settings["ring_settings"],
            initial_positions=settings["initial_positions"],
            reflector=settings["reflector"],
            plugboard=settings["plugboard"],
        )
        ciphertext = machine.encrypt(msg["plaintext"])

        # Verify round-trip immediately
        machine.reset()
        decrypted = machine.encrypt(ciphertext)
        assert decrypted == msg["plaintext"].upper().replace(" ", ""), (
            f"Round-trip failed for {task_id}: "
            f"expected {msg['plaintext']}, got {decrypted}"
        )

        # Generate cribs
        cribs = _generate_cribs(msg["plaintext"], difficulty, rng)

        # Generate revealed info
        revealed = _revealed_info(settings, difficulty)

        # Format ciphertext in 5-letter groups for display
        ciphertext_grouped = " ".join(
            ciphertext[i:i + 5] for i in range(0, len(ciphertext), 5)
        )

        tasks[task_id] = {
            "id": task_id,
            "split": split,
            "difficulty": difficulty,
            "category": msg["category"],
            "plaintext": msg["plaintext"],
            "ciphertext": ciphertext,
            "ciphertext_grouped": ciphertext_grouped,
            "rotor_order": settings["rotor_order"],
            "ring_settings": settings["ring_settings"],
            "initial_positions": settings["initial_positions"],
            "reflector": settings["reflector"],
            "plugboard": [list(p) for p in settings["plugboard"]],
            "revealed_info": revealed,
            "cribs": cribs,
            "intercept": msg["intercept"],
        }

    return tasks


# Build tasks at module load time
ALL_TASKS = build_all_tasks()
ALL_SPLITS = ["train", "test"]


def get_task_counts() -> dict:
    """Get task counts by split and difficulty."""
    counts: dict[str, dict[str, int]] = {}
    for task in ALL_TASKS.values():
        split = task["split"]
        diff = task["difficulty"]
        if split not in counts:
            counts[split] = {}
        counts[split][diff] = counts[split].get(diff, 0) + 1
    return counts
