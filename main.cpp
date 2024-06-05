#include "include/OMRUtil.h"
#include "include/GOMR.h"
#include "include/OMR.h"
#include "include/OMRopt.h"
#include "include/OMRdos.h"
#include "include/MRE.h"
#include <openssl/aes.h>
#include <string.h>

using namespace seal;

string AGOMR = "agomr";
string FGOMR = "fgomr";
string PERFOMR1 = "perfomr1";
string PERFOMR2 = "perfomr2";
string DOS = "dos";
string DOS_ATTACK = "dos-attack"; // attack on perfomr

int main(int argc, char* argv[]) {
    cout << "+------------------------------------+" << endl;
    cout << "| Benchmark Test                     |" << endl;
    cout << "+------------------------------------+" << endl;

    int selection = 0;
    if (argc == 1) {
DEFAULT:
        bool valid = true;
        do
        {
            cout << endl << "> Run demos (1 ~ 33) or exit (0): ";
            if (!(cin >> selection))
            {
                valid = false;
            }
            else if (selection < 0 || selection > 33)
            {
                valid = false;
            }
            else
            {
                valid = true;
            }
            if (!valid)
            {
                cout << "  [Beep~~] valid option: type 0 ~ 33" << endl;
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }
        } while (!valid);
    } else {
        if (AGOMR.compare(argv[1]) == 0) {
            selection = 25;
            party_size_glb = atoi(argv[2]);
            id_size_glb = ceil(float(60 * party_size_glb + 128) / float(16) + party_size_glb + 1);

            batch_ntt_glb = 1;
            for (; batch_ntt_glb < id_size_glb; batch_ntt_glb *= 2) {}
        } else if (FGOMR.compare(argv[1]) == 0) {
            selection = 31;
            party_size_glb = atoi(argv[2]);
            partial_size_glb = ceil(float(60 * party_size_glb + 128) / float(16) + party_size_glb + 1);
	} else if (PERFOMR1.compare(argv[1]) == 0) {
	    selection = 5;
	    default_param_set = true;
	    numcores = atoi(argv[2]);
	    party_size_glb = atoi(argv[3]);
	    numOfTransactions_glb = atoi(argv[4]);
	    num_of_pertinent_msgs_glb = atoi(argv[5]);
	} else if (PERFOMR2.compare(argv[1]) == 0) {
        selection = 5;
	    default_param_set = false;
	    numcores = atoi(argv[2]);
	    party_size_glb = atoi(argv[3]);
	    numOfTransactions_glb = atoi(argv[4]);
	    num_of_pertinent_msgs_glb = atoi(argv[5]);
	} else if (DOS.compare(argv[1]) == 0) {
        selection = 34;
	    numcores = atoi(argv[2]);
	    party_size_glb = atoi(argv[3]);
	    numOfTransactions_glb = atoi(argv[4]);
	    num_of_pertinent_msgs_glb = atoi(argv[5]);
        } else if (DOS_ATTACK.compare(argv[1]) == 0){
	  selection = 35;
	  attack = true;
	  default_param_set = true;
	  numcores = 1;
	  party_size_glb = 2;
	  numOfTransactions_glb = 32768;
	  num_of_pertinent_msgs_glb = 50;
	} else {
            goto DEFAULT;
        }
    }

    switch (selection)
        {
        case 1:
            OMDlevelspecificDetectKeySize();
            break;

        case 2:
            levelspecificDetectKeySize();
            break;

        case 3:
            numcores = 1;
            OMD1p();
            break;

        case 4:
            numcores = 1;
            OMR3();
            break;

        case 5:
            OMR3_opt();
            break;
        
        case 6:
            numcores = 2;
            OMR2();
            break;

        case 7:
            numcores = 2;
            OMR3();
            break;
        
        case 8:
            numcores = 4;
            OMR2();
            break;

        case 9:
            numcores = 4;
            OMR3();
            break;

        case 10:
            numcores = 1;
            GOMR1();
            break;

        case 11:
            numcores = 2;
            GOMR1();
            break;

        case 12:
            numcores = 4;
            GOMR1();
            break;

        case 13:
            numcores = 1;
            GOMR2();
            break;

        case 14:
            numcores = 2;
            GOMR2();
            break;

        case 15:
            numcores = 4;
            GOMR2();
            break;

        case 16:
            numcores = 1;
            GOMR1_ObliviousMultiplexer();
            break;

        case 17:
            numcores = 2;
            GOMR1_ObliviousMultiplexer();
            break;

        case 18:
            numcores = 4;
            GOMR1_ObliviousMultiplexer();
            break;

        case 19:
            numcores = 1;
            GOMR2_ObliviousMultiplexer();
            break;

        case 20:
            numcores = 2;
            GOMR2_ObliviousMultiplexer();
            break;

        case 21:
            numcores = 4;
            GOMR2_ObliviousMultiplexer();
            break;

        case 22:
            numcores = 1;
            GOMR1_ObliviousMultiplexer_BFV();
            break;

        case 23:
            numcores = 2;
            GOMR1_ObliviousMultiplexer_BFV();
            break;

        case 24:
            numcores = 4;
            GOMR1_ObliviousMultiplexer_BFV();
            break;

        case 25:
            numcores = 1;
            GOMR2_ObliviousMultiplexer_BFV();
            break;

        case 26:
            numcores = 2;
            GOMR2_ObliviousMultiplexer_BFV();
            break;

        case 27:
            numcores = 4;
            GOMR2_ObliviousMultiplexer_BFV();
            break;

        case 28:
            numcores = 1;
            GOMR1_FG();
            break;

        case 29:
            numcores = 2;
            GOMR1_FG();
            break;

        case 30:
            numcores = 4;
            GOMR1_FG();
            break;

        case 31:
            numcores = 1;
            GOMR2_FG();
            break;

        case 32:
            numcores = 2;
            GOMR2_FG();
            break;

        case 33:
            numcores = 4;
            GOMR2_FG();
            break;

	case 34:
		// numcores = 1;
		OMR3_dos();
		break;

	case 35:
	  for (int i = 0; i < 3; i++) {
	    OMR3_opt();
	  }
	  break;

        case 0:
            return 0;
        }
}
