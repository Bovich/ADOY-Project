using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using VirusTotalNet;
using VirusTotalNet.Objects;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;

namespace WebApplication1.Controllers
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
                return ("Scan ID: " + urlReport.ScanId + "Message: " + urlReport.VerboseMsg);
            }
            else
            {
                UrlScanResult urlResult = await virusTotal.ScanUrlAsync(scanUrl);
                return ("Scan ID: " + urlResult.ScanId + "Message: " + urlResult.VerboseMsg);
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
                return ("Scan ID: " + ipReport + "Message: " + ipReport.VerboseMsg);
            }
            else
            {
                // UrlScanResult urlResult = await virusTotal.ScanUrlAsync(scanUrl);
                // return ("Scan ID: " + urlReport.ScanId + "Message: " + urlReport.VerboseMsg);
            }

            return "success";
        }

        // POST api/values/file
        [HttpPost("file")]
        public ActionResult<string> VirusTotalCheckFile([FromBody] FileResult value)
        {
            return "Sup?";
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
