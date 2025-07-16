#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstring>
using namespace std;

enum logLevel
{
    SILENT,  // no log whatsoever
    ERROR,   // log errors only
    WARNING, // log warnings too
    INFO,    // log basic infos
    DEBUG,
    ADVANCED // log everything
};

class Logger
{
public:
    // Constructor
    Logger(const string &filename)
    {
        logFile.open(filename, ios::app);
        if (!logFile.is_open())
        {
            cerr << "Error opening the log file." << endl;
        }
    }

    // Destructor: Closes the log file
    ~Logger() { logFile.close(); }

    // creates a log entry
    void log(logLevel logLevel, const string &message)
    {
        // Get current timestamp
        time_t now = time(0);
        tm *timeinfo = localtime(&now);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

        // create log entry
        ostringstream logEntry;
        logEntry << "[" << timestamp << "]"
                 << levelToString(logLevel) << ":" << message
                 << endl;

        // Output dans la console
        cout << logEntry.str();

        // output dans le fichier de log
        if (logFile.is_open())
        {
            logFile << logEntry.str();
            logFile.flush(); // Writes immediatly
        }
    }

private:
    ofstream logFile;

    // converts log level to a string
    string levelToString(logLevel level)
    {
        switch (level)
        {
        case SILENT:
            return "SILENT";
        case ERROR:
            return "ERROR";
        case WARNING:
            return "WARNING";
        case INFO:
            return "INFO";
        case DEBUG:
            return "DEBUG";
        case ADVANCED:
            return "ADVANCED";
        default:
            return "UNKNOWN";
        }
    }
};

class Parameters
{
public:
    bool dirs;
    bool subs;
    bool help;
    bool error;
    char *link;
    logLevel level;
    ifstream wordlistSubs;
    ifstream wordlistDirs;
    ofstream logFile;

    Parameters()
    {
        dirs = false;
        subs = false;
        help = false;
        error = false;
        level = INFO;
        link = NULL;
    }
};

void printHelp(char *functionName)
{
    cout << endl
         << "usage: fuzzer [options] <uri>" << endl;
    cout << endl
         << "Options:" << endl;
    cout << "   -d [wordlist] | --directories [wordlist] : Searches for directories on the specified url. If wordlist is not included, it takes /usr/share/wordlists/dirb/big.txt as default file" << endl;
    cout << "   -s [wordlist] | --subdomains [wordlist] : Searches for subdomains of the specified url. For this option, it is recommended to not specify a folder in the url. Default file is /usr/share/wordlists/subs/medium.txt" << endl;
    cout << "   -h | --help : displays this text" << endl;
    cout << "   -v | --verbose : set verbose level to DEBUG" << endl;
    cout << "   -o <file>| --output <file>: set <file> as the file for storing the output" << endl;
    cout << "   if options are all in one flag (i.e. -sdo for example), the parameters for the names of the input and output files are gonna be taken in order (i.e. -sdo <subs file> <dirs file> <output file> for example)" << endl;
}

void printError(char *functionName)
{
    cout << "Error while executing, check the parameters used. You need to at least include a link to test" << endl;
    printHelp(functionName);
}

int searchParameters(int argc, char *argv[], Parameters *pm, int i, char *option)
{
    // returns the number of arguments we skip, intended for treating the input and output files
    if (option == NULL)
    {
        option = argv[i];
    }

    if (strcmp(option, "-d") == 0 || strcmp(option, "--directories") == 0)
    {
        pm->dirs = true;
        if ((i + 1 < argc - 1) && (argv[i + 1][0] != '-'))
        { // searching for a file
            pm->wordlistDirs.open(argv[i + 1]);
            if (!pm->wordlistDirs.is_open())
            {
                pm->error = true;
                cout << "Errror, couldn't open the wordlist for directory fuzzing" << endl;
            }
            else
            {
                cout << "reading the dirb file " << argv[i + 1] << endl;
            }
            return 1;
        }
        else
        { // if no file has been found
            cout << "No file has been found for the directories search, opening /usr/share/wordlists/dirb/big.txt" << endl;
            pm->wordlistDirs.open("/usr/share/wordlists/dirb/big.txt");
            if (!pm->wordlistDirs.is_open())
            {
                pm->error = true;
                cout << "Errror, couldn't open the wordlist for directory fuzzing" << endl;
            }
            else
            {
                cout << "reading the dirb file /usr/share/wordlists/dirb/big.txt" << endl;
            }
        }
        return 0;
    }
    else if (strcmp(option, "-s") == 0 || strcmp(option, "--subdomains") == 0)
    {
        pm->subs = true;
        if ((i + 1 < argc - 1) && (argv[i + 1][0] != '-'))
        {
            pm->wordlistSubs.open(argv[i + 1]);
            if (!pm->wordlistSubs.is_open())
            {
                pm->error = true;
                cout << "Errror, couldn't open the wordlist for sub-domains fuzzing" << endl;
            }
            else
            {
                cout << "reading the subs file " << argv[i + 1] << endl;
            }
            return 1;
        }
        else
        {
            cout << "No file has been found for the subdomains search, opening /usr/share/wordlists/subs/medium.txt" << endl;
            pm->wordlistDirs.open("/usr/share/wordlists/subs/medium.txt");
            if (!pm->wordlistSubs.is_open())
            {
                pm->error = true;
                cout << "Errror, couldn't open the wordlist for sub-domains fuzzing" << endl;
            }
            else
            {
                cout << "reading the subs file /usr/share/wordlists/subs/medium.txt" << endl;
            }
        }
        return 0;
    }
    else if (strcmp(option, "-h") == 0 || strcmp(option, "--help") == 0)
    {
        pm->help = true; // 0 indicates the help indications must be printed
        return 0;
    }
    else if (strcmp(option, "-v") == 0 || strcmp(option, "--verbose") == 0)
    {
        pm->level = DEBUG;
        return 0;
    }
    else if (strcmp(option, "-o") == 0 || strcmp(option, "--output") == 0)
    {
        if (i + 1 >= argc - 1)
        {
            pm->error = true;
            cout << "Error, not enough arguments, file probably is missing" << endl;
            return 0;
        }
        pm->logFile.open(argv[i + 1]);
        if (!pm->logFile.is_open())
        {
            pm->error = true;
            cout << "There was a problem when opening the file, please check if the parameter is correct" << endl;
        }
        else
        {
            cout << "writing the output file " << argv[i + 1] << endl;
        }
        // i++;
        return 1;
    }
    else
    {
        // If options are stacked in one string, we check them one by one, that's why we need a recursive searchParameters function
        int index = 1;
        int shift = 0;
        while ((option[index] != '\0') && (option[index] == 'd' || option[index] == 's' || option[index] == 'h' || option[index] == 'v' || option[index] == 'o'))
        {
            char *param = (char *)malloc(3 * sizeof(char));
            param[0] = '-';
            param[1] = option[index];
            param[2] = '\0';
            // create a new option for each letter in this group of options and go through with it. We need recursion for that
            shift = searchParameters(argc, argv, pm, i, param);
            i += shift;
            index++;
        }
        return shift;
    }
}

void loopParameters(int argc, char *argv[], Parameters *pm)
{
    // go through parameters
    for (int i = 1; i < argc - 1; i++)
    {
        // we only go to argc - 1 as the last argument is supposed to be the link
        i += searchParameters(argc, argv, pm, i, NULL);
    }
}

char *parseLink(char *lastArg, Parameters *pm)
{
    return lastArg;
}

int main(int argc, char *argv[])
{
    if (argc == 1)
    {
        cout << "Fetching for a new option" << endl;
        printError(argv[0]);
        return 0;
    }

    // go through parameters
    Parameters p = Parameters();
    Parameters *pm = &p;
    loopParameters(argc, argv, pm);

    pm->link = parseLink(argv[argc - 1], pm); // parse the link obtained
    cout << "Code is being executed on the link '" << pm->link << "'" << endl;

    // error or help handling
    if (pm->error == true)
    {
        printError(argv[0]);
        return 0;
    }
    else if (pm->help == true)
    {
        printHelp(argv[0]);
        return 0;
    }

    // Main function

    return 0;
}