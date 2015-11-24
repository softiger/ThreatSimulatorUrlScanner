using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ThreatSimulatorUrlScanner.WebsiteDataService;
using System.Data;
using Websense.Utility;
using System.Threading.Tasks;
using System.Threading;
using System.Net;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Reflection;

namespace ThreatSimulatorUrlScanner
{
    class Scanner
    {
        private DataTable _scanResult;
        WebsiteDataSoapClient _websiteDataSoapClient = new WebsiteDataSoapClient();
        private string _token = string.Empty;
        private string _userName = string.Empty;
        private static string _logFilePath =
            _logFilePath = string.Format(Constants.LogFileFullPathFormat, System.IO.Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), string.Format(Constants.LogFileNameFormat, DateTime.Now));

        public void Run()
        {
            this._scanResult = CreateScanResultTable();
            this._token = WebsiteDataUtility.GetToken(this._userName, ConfigUtil.GetConfigString(Constants.CskAuthorizedPasswordKey));
            this._userName = ConfigUtil.GetConfigString(Constants.CskAuthorizedUserNameKey);
            List<TestCase> testCases = WebsiteDataUtility.GetScanableTestCases(this._token, this._userName);
            PrintLog(string.Format("{0} Test Cases in total", testCases.Count));
            PrintLog("===============================================================");
            foreach (var testcase in testCases)
            {
                PrintLog(string.Format("Begin scan Test Case: {0} with url: {1}", testcase.Id, testcase.Input));
                this.Scan(testcase);
                PrintLog(string.Format("End scan Test Case: {0} with url: {1}", testcase.Id, testcase.Input));
                PrintLog();
            }

            if (this._scanResult != null && this._scanResult.Rows.Count > 0)
            {
                PrintLog("Begin StoreScanTestCaseResults");
                this.StoreScanTestCaseResults();
                PrintLog("End StoreScanTestCaseResults");
            }
        }

        private void Scan(TestCase testCase)
        {
            DataRow row = this._scanResult.NewRow();
            row[Constants.TestID] = testCase.Id;
            row[Constants.DateScanned] = DateTime.Now.ToString();
            row[Constants.ResolvedIPAddress] = this.ResovleIPAddress(testCase);

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(testCase.Input);
            request.Method = WebRequestMethods.Http.Get;
            try
            {
                request.BeginGetResponse((iarr) =>
                {
                    ProcessHttpResponse(testCase, row, request, iarr);
                },
                null);
            }
            catch (WebException webex)
            {
                if (webex.Response != null)
                {
                    row[Constants.ScanHTTPResult] = ((HttpWebResponse)webex.Response).StatusCode;
                    webex.Response.Close();
                }

                PrintLog(webex.Message);
            }
            catch (Exception ex)
            {
                row[Constants.ScanHTTPResult] = Constants.HttpUnavailable;

                PrintLog(ex.Message);
            }

            row[Constants.RealTimeSecurityCat] = WebsiteDataUtility.GetUrlRealTimeCat(this._token, this._userName, testCase.Input);
            this._scanResult.Rows.Add(row); ;
        }

        [DllImport(@"urlmon.dll", CharSet = CharSet.Auto)]
        private extern static System.UInt32 FindMimeFromData(
            System.UInt32 pBC,
            [MarshalAs(UnmanagedType.LPStr)] System.String pwzUrl,
            [MarshalAs(UnmanagedType.LPArray)] byte[] pBuffer,
            System.UInt32 cbSize,
            [MarshalAs(UnmanagedType.LPStr)] System.String pwzMimeProposed,
            System.UInt32 dwMimeFlags,
            out System.UInt32 ppwzMimeOut,
            System.UInt32 dwReserverd
        );

        private static string GetMimeFromBytes(byte[] buffer)
        {
            try
            {
                System.UInt32 mimetype;
                FindMimeFromData(0, null, buffer, 256, null, 0, out mimetype, 0);
                System.IntPtr mimeTypePtr = new IntPtr(mimetype);
                string mime = Marshal.PtrToStringUni(mimeTypePtr);
                Marshal.FreeCoTaskMem(mimeTypePtr);
                return mime;
            }
            catch
            {
                return "unknown/unknown";
            }
        }

        private static void ProcessHttpResponse(TestCase testCase, DataRow row, HttpWebRequest request, IAsyncResult iarr)
        {
            try
            {
                if (testCase.EnableContentScan && !string.IsNullOrWhiteSpace(testCase.ContentScanCheckString))
                {
                    row[Constants.ContentScannedFor] = testCase.ContentScanCheckString;
                }
                else
                {
                    row[Constants.ContentScannedFor] = null;
                }
                row[Constants.FoundContent] = null;

                using (WebResponse response = request.EndGetResponse(iarr))
                {
                    row[Constants.ScanHTTPResult] = (int)((HttpWebResponse)response).StatusCode;
                    row[Constants.BytesXfered] = response.ContentLength;

                    string responseDetails = null;
                    string mimeType = "text/";
                    using (Stream stream = response.GetResponseStream())
                    {
                        // check first 256 bytes for mime type
                        List<byte> fullResponseBuffer = new List<byte>();
                        byte[] buffer = new byte[256];
                        int byteCount = stream.Read(buffer, 0, 256);
                        if (byteCount > 0)
                        {
                            mimeType = GetMimeFromBytes(buffer);
                            // store these bytes for the full response
                            fullResponseBuffer.AddRange(buffer.Take(byteCount));
                        }
                        PrintLog("mimeType: " + mimeType);
                        if (mimeType.ToLower().StartsWith("text/"))
                        {
                            // finish getting the stream into the buffer
                            while (true)
                            {
                                byte[] tmpBuffer = new byte[1024];
                                int bytesRead = stream.Read(tmpBuffer, 0, tmpBuffer.Length);
                                fullResponseBuffer.AddRange(tmpBuffer.Take(bytesRead));
                                if (bytesRead == 0)
                                    break;
                            }

                            responseDetails = Encoding.Default.GetString(fullResponseBuffer.ToArray());
                            row[Constants.ScanResponseText] = responseDetails;

                            if (testCase.EnableContentScan && !string.IsNullOrWhiteSpace(testCase.ContentScanCheckString))
                            {
                                row[Constants.FoundContent] = responseDetails.IndexOf(testCase.ContentScanCheckString, StringComparison.InvariantCultureIgnoreCase) > -1 ? Constants.FoundContentValue :
                                    Constants.NotFoundContentValue;
                            }
                        }
                    }
                }
            }
            catch (WebException webex)
            {
                PrintLog(webex.ToString());
                if (webex.Response != null)
                {
                    row[Constants.ScanHTTPResult] = (int)((HttpWebResponse)webex.Response).StatusCode;
                    webex.Response.Close();
                }
                else
                {
                    row[Constants.ScanHTTPResult] = Constants.HttpUnavailable;
                }
            }
            catch (Exception ex)
            {
                PrintLog(ex.ToStringWithData());
                row[Constants.ScanHTTPResult] = Constants.HttpUnavailable;
            }
        }

        private string ResovleIPAddress(TestCase testCase)
        {
            string ip = null;
            try
            {
                Uri uri = new Uri(testCase.Input);
                IPHostEntry Host = Dns.GetHostEntry(uri.Host);
                ip = Host.AddressList.First().ToString();
            }
            catch
            {
                PrintLog(string.Format("Get Resolved IP Address failed for Test Case: {0} with URL: {1}",
                    testCase.Id, testCase.Input));
            }

            return ip;
        }

        private void StoreScanTestCaseResults()
        {
            if (this._scanResult != null)
            {
                TestCaseScanResult testCaseScanResult = new TestCaseScanResult();
                List<TestCase> testCases = new List<TestCase>();
                foreach (DataRow item in this._scanResult.Rows)
                {
                    TestCase tc = new TestCase();
                    tc.Id = item[Constants.TestID] as string;
                    tc.DateScanned = SafeConvert.ToDate(item[Constants.DateScanned]);
                    tc.ScanHttpResult = item[Constants.ScanHTTPResult] as string;
                    tc.RealTimeSecCat = item[Constants.RealTimeSecurityCat] as string;
                    tc.BytesXfer = SafeConvert.ToInt(item[Constants.BytesXfered]);

                    tc.ResolvedIpAddress = item[Constants.ResolvedIPAddress] as string;
                    tc.ContentScanCheckString = item[Constants.ContentScannedFor] as string;
                    tc.ScanResponseText = item[Constants.ScanResponseText] as string;

                    string foundContent = SafeConvert.ToString(item[Constants.FoundContent]);
                    if (!string.IsNullOrEmpty(foundContent))
                    {
                        tc.FoundContent = foundContent == Constants.FoundContentValue;
                    }
                    else
                    {
                        tc.FoundContent = null;
                    }

                    testCases.Add(tc);
                }
                testCaseScanResult.TestCases = testCases.ToArray();
                testCaseScanResult.Token = this._token;
                testCaseScanResult.Username = this._userName;

                WebsiteDataUtility.StoreScanTestCaseResults(testCaseScanResult);
            }
        }

        private static DataTable CreateScanResultTable()
        {
            DataTable dt = new DataTable();
            dt.Columns.Add(new DataColumn(Constants.TestID));
            dt.Columns.Add(new DataColumn(Constants.DateScanned));
            dt.Columns.Add(new DataColumn(Constants.ScanHTTPResult));
            dt.Columns.Add(new DataColumn(Constants.ResolvedIPAddress));
            dt.Columns.Add(new DataColumn(Constants.BytesXfered));
            dt.Columns.Add(new DataColumn(Constants.ContentScannedFor));
            dt.Columns.Add(new DataColumn(Constants.FoundContent));
            dt.Columns.Add(new DataColumn(Constants.RealTimeSecurityCat));
            dt.Columns.Add(new DataColumn(Constants.ScanResponseText));

            return dt;
        }

        public static void PrintLog(string output = "\n")
        {
            if (ConfigUtil.GetConfigBool(Constants.EnablePrintLog, false))
            {
                string parentDirectory = Path.GetDirectoryName(_logFilePath);
                if (!Directory.Exists(parentDirectory))
                {
                    Directory.CreateDirectory(parentDirectory);
                }

                File.AppendAllText(_logFilePath, output);
                if(output != "\n")
                {
                    File.AppendAllText(_logFilePath, Environment.NewLine);
                }
            }
        }
    }

    class Constants
    {
        public const string TestID = "TestID";
        public const string DateScanned = "DateScanned";
        public const string ScanHTTPResult = "ScanHTTPResult";
        public const string ResolvedIPAddress = "ResolvedIPAddress";
        public const string BytesXfered = "BytesXfered";
        public const string ContentScannedFor = "ContentScannedFor";
        public const string FoundContent = "FoundContent";
        public const string RealTimeSecurityCat = "RealTimeSecurityCat";
        public const string ScanResponseText = "ScanResponseText";

        public const string CskAuthorizedUserNameKey = "CskAuthorizedUserName";
        public const string CskAuthorizedPasswordKey = "CskAuthorizedPassword";
        public const string NumberOfThreadsKey = "NumberOfThreads";

        public const string EnablePrintLog = "EnablePrintLog";
        public const string LogFileNameFormat = "{0:yyyy-MM-dd_hh-mm-ss-tt}";
        public const string LogFileFullPathFormat = "{0}\\Logs\\{1}.txt";

        public const string HttpUnavailable = "NOCON";
        public const string FoundContentValue = "1";
        public const string NotFoundContentValue = "0";
    }
}
