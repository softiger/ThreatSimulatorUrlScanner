using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Websense.Utility;

namespace ThreatSimulatorUrlScanner
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Scanner.PrintLog("Begin Scanning...");

                Scanner scanner = new Scanner();
                scanner.Run();

                Scanner.PrintLog("Scan Ended.");
            }
            catch (Exception ex)
            {
                Scanner.PrintLog(ex.ToStringWithData());
            }
        }
    }
}
