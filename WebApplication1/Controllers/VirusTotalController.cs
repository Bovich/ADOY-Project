using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using VirusTotalNet;
using VirusTotalNet.Objects;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;

namespace VirusTotalNet
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        VirusTotal virusTotal = new VirusTotal("50c1c91e9bfc7cb858022a0cbeaf1ba0f8782dbbd506be82f71b1e3f243000cf");

        //Use HTTPS instead of HTTP
        //virusTotal.UseTLS = true;

        // POST api/values/url
        [HttpPost("url")]
        public async Task<ActionResult<string>> VirusTotalCheckUrlAsync([FromBody] string scanUrl)
        {
            UrlReport urlReport = await virusTotal.GetUrlReportAsync(scanUrl);

            bool hasUrlBeenScannedBefore = urlReport.ResponseCode == UrlReportResponseCode.Present;

            //If the url has been scanned before, the results are embedded inside the report.
            if (hasUrlBeenScannedBefore)
            {
                return ("Number of scans: " +urlReport.Total +"      "+ "Positive: " + urlReport.Positives);
            }
            else
            {
                UrlScanResult urlResult = await virusTotal.ScanUrlAsync(scanUrl);
                UrlReport newUrlReport = await virusTotal.GetUrlReportAsync(scanUrl);
                return ("Url is being scanned, come back later for the result.");
            }
        }

        // POST api/values/ip
        [HttpPost("ip")]
        public async Task<ActionResult<string>> VirusTotalCheckIpAsync([FromBody] string scanIp)
        {
            IPReport ipReport = await virusTotal.GetIPReportAsync(scanIp);

            bool hasIpBeenScannedBefore = ipReport.ResponseCode == IPReportResponseCode.Present;

            //If the url has been scanned before, the results are embedded inside the report.
            if (hasIpBeenScannedBefore)
            {
                return ("Scan ID:       " + ipReport.DetectedUrls.Count + "     Message:    " + ipReport.VerboseMsg);
            }
            else
            {
                UrlScanResult ipResult = await virusTotal.ScanUrlAsync(scanIp);
                return ("IP Address is being scanned, come back later for the result." + "Scan ID: " + ipReport.DetectedUrls.Count + "Message: " + ipReport.VerboseMsg);
            }

            return "success";
        }

        // POST api/values/file
        [HttpPost("file")]
        public async Task<ActionResult<string>> VirusTotalCheckFileAsync([FromBody]FileInfo value)
        {
            //byte[] newvalue = Encoding.ASCII.GetBytes(value);
            FileReport fileReport = await virusTotal.GetFileReportAsync(value);

            bool hasFileBeenScannedBefore = fileReport.ResponseCode == FileReportResponseCode.Present;

            //If the file has been scanned before, the results are embedded inside the report.
            if (hasFileBeenScannedBefore)
            {
                return ("Number of scans: " + fileReport.Total + "      " + "Positive: " + fileReport.Positives);
            }
            else
            {
                //UrlScanResult fileResult = await virusTotal.ScanFileAsync(value);
                return ("File is being scanned, come back later for the result." + "Scan ID: " + fileReport.ScanId + "Message: " + fileReport.VerboseMsg);
            }
        }

        private static void PrintScan(UrlScanResult scanResult)
        {
            Console.WriteLine("Scan ID: " + scanResult.ScanId);
            Console.WriteLine("Message: " + scanResult.VerboseMsg);
            Console.WriteLine();
        }

        private static void PrintScan(ScanResult scanResult)
        {
            Console.WriteLine("Scan ID: " + scanResult.ScanId);
            Console.WriteLine("Message: " + scanResult.VerboseMsg);
            Console.WriteLine();
        }

        private static void PrintScan(FileReport fileReport)
        {
            Console.WriteLine("Scan ID: " + fileReport.ScanId);
            Console.WriteLine("Message: " + fileReport.VerboseMsg);

            if (fileReport.ResponseCode == FileReportResponseCode.Present)
            {
                foreach (KeyValuePair<string, ScanEngine> scan in fileReport.Scans)
                {
                    Console.WriteLine("{0,-25} Detected: {1}", scan.Key, scan.Value.Detected);
                }
            }

            Console.WriteLine();
        }

        private static void PrintScan(UrlReport urlReport)
        {
            Console.WriteLine("Scan ID: " + urlReport.ScanId);
            Console.WriteLine("Message: " + urlReport.VerboseMsg);

            if (urlReport.ResponseCode == UrlReportResponseCode.Present)
            {
                foreach (KeyValuePair<string, UrlScanEngine> scan in urlReport.Scans)
                {
                    Console.WriteLine("{0,-25} Detected: {1}", scan.Key, scan.Value.Detected);
                }
            }

            Console.WriteLine();
        }
    }
}
