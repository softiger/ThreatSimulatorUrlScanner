using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ThreatSimulatorUrlScanner.WebsiteDataService;
using Websense.Utility;

namespace ThreatSimulatorUrlScanner
{
    class WebsiteDataUtility
    {
        public static List<TestCase> GetScanableTestCases(string token, string userName)
        {
            List<TestCase> testCases = new List<TestCase>();

            WebsiteDataSoapClient client = new WebsiteDataSoapClient();
            TestCasesResponse testCaseResponse = client.GetScanableTestCases(token, userName);
            testCases = testCaseResponse.TestCases.ToList<TestCase>();

            return testCases;
        }

        public static string GetUrlRealTimeCat(string token, string userName, string url)
        {
            string cat = string.Empty;

            WebsiteDataSoapClient client = new WebsiteDataSoapClient();
            RealTimeCategoryResponse realTimeCategoryResponse = client.GetUrlRealTimeCat(token, userName, url);
            if (realTimeCategoryResponse.Errors.Count().Equals(0))
            {
                cat = realTimeCategoryResponse.RealTimeCategory;
            }
            return cat;
        }

        public static void StoreScanTestCaseResults(TestCaseScanResult testCaseScanResult)
        {
            WebsiteDataSoapClient client = new WebsiteDataSoapClient();

            string url = client.Endpoint.ListenUri.ToString() + "/StoreScanTestCaseResults";
            
            string postData = @"{ ""testCaseScanResult"" : " + Newtonsoft.Json.JsonConvert.SerializeObject(testCaseScanResult) + " }";
            
            string result = string.Empty;
            Uri uri = new Uri(url);
            System.Net.HttpWebRequest request = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(uri);
            request.Method = "POST";
            request.ContentType = "application/json; charset=utf-8";
            request.ContentLength = System.Text.Encoding.UTF8.GetByteCount(postData);
            
            using (System.IO.Stream writeStream = request.GetRequestStream())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(postData);
                writeStream.Write(bytes, 0, bytes.Length);
                writeStream.Close();

                using (System.Net.HttpWebResponse response = (System.Net.HttpWebResponse)request.GetResponse())
                {
                    using (System.IO.Stream responseStream = response.GetResponseStream())
                    {
                        using (System.IO.StreamReader readStream = new System.IO.StreamReader(responseStream, Encoding.UTF8))
                        {
                            result = readStream.ReadToEnd();
                            readStream.Close();
                        }
                        responseStream.Close();
                    }
                    response.Close();
                }
            }

            //client.StoreScanTestCaseResults(testCaseScanResult);
        }

        public static string GetToken(string userName, string password)
        {
            string token = string.Empty;
            WebsiteDataSoapClient client = new WebsiteDataSoapClient();
            LoginResponse response = client.Login(ConfigUtil.GetConfigString(Constants.CskAuthorizedUserNameKey),
                ConfigUtil.GetConfigString(Constants.CskAuthorizedPasswordKey));

            if (response.Errors.Count().Equals(0))
            {
                token = response.Token;
            }

            return token;
        }
    }
}
