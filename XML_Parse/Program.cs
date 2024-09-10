using log4net;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using System.Management;
using System.Threading;
using System.Security.Cryptography;
using System.Collections.Concurrent;

namespace XML_Parse
{
    class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public String Dataset { get; set; }
        public String ThreadId { get; set; }
        public String LogLevel { get; set; }
        public String ErrorMessage { get; set; }
    }

    class EventEntry
    {
        public String Event { get; set; }
        public int Total { get; set; }
        public int Processed { get; set; }
    }

    internal class Program
    {
        private static readonly ILog log = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        private static StringBuilder msgBuilder = new StringBuilder();
        private static DataTable DTServer = new DataTable();

        static void Main(String[] args)
        {
            try
            {
                DeleteLogFiles();
                DTServer.Columns.Add("IP");
                DTServer.Columns.Add("Username");
                DTServer.Columns.Add("Password");
                msgBuilder.Append("<style>\n#security \n{width: 99%;border-radius:10px;border-spacing: 0;font-family:'Trebuchet MS', sans-serif;margin-left: auto;margin-right: auto;}\n#security td, #security th \n{border: 1px solid #ddd;padding: 10px;}\n#security tr:nth-child(even)\n{background-color: #f2f2f2;}\n#security th \n{padding-top: 12px;padding-bottom: 12px;text-align: center;background-color: #5F9EA0;color: white;}\n#myDiv\n{border: 2px outset #5F9EA0;text-align: center;}\n</style>\n<body style=\"font-family:'Trebuchet MS', sans-serif;\">\nDear Admin,</br>Below is the summary of Content Manager Monitoring Tool on " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "\n</br></br>");
                GetCpuDetails();                
                LoadServerDetails();
                BuildReport();
                GenerateEmailReport();
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        private static XmlElement GetXML()
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load("CM_Monitor.xml");
            XmlElement root = xmlDoc.DocumentElement;
            return root;
        }

        private static void LoadServerDetails()
        {
            foreach (XmlElement serverDetails in GetXML().SelectNodes("CM_Monitor/ServerDetails/Servers"))
            {
                DTServer.Rows.Add(serverDetails.GetAttribute("IP"), serverDetails.GetAttribute("Username"), serverDetails.GetAttribute("Password"));
                GetCpuDetails(serverDetails.GetAttribute("IP"));
            }
        }

        private static void BuildReport()
        {
            msgBuilder.Append("\n<div id='mydiv'>\n<h3>CM Components Monitoring</h3>\n<table id='security' border='2'>\n<tr>\n<th>Environment</th>\n<th>Servers</th>\n<th>Services</th>\n<th>CM Components</th>\n<th>Monitoring Components</th>\n<th>Status</th>");
            foreach (XmlElement environmentNode in GetXML().SelectNodes("CM_Monitor/Environments/Environment"))
            {
                int wgscount = 0, dscount = 0;
                msgBuilder.Append("\n<tr>\n<td rowspan=\"EnviCount\">" + environmentNode.GetAttribute("Name") + "</td>");
                log.Info("Environment: " + environmentNode.GetAttribute("Name"));
                foreach (XmlElement workgroupNode in environmentNode.SelectNodes("WorkgroupServers/Workgroup"))
                {
                    wgscount += 1;
                    ProcessWorkgroup(workgroupNode, environmentNode.GetAttribute("Name"));
                }
                foreach (XmlElement datasetNode in environmentNode.SelectNodes("Datasets/Dataset"))
                {
                    dscount += 1;
                    ProcessDataset(datasetNode);
                }
                int totalcount = (wgscount * 11) + (dscount * 3);
                msgBuilder.Replace("EnviCount", totalcount.ToString());
            }
            foreach (XmlElement windowsNode in GetXML().SelectNodes("CM_Monitor/WindowsEvent"))
            {
                foreach (XmlElement servicesNode in windowsNode.SelectNodes("Services"))
                {
                    DateTime lastUpdated = DateTime.Now.AddDays(-5);
                    if (!String.IsNullOrEmpty(servicesNode.GetAttribute("LastUpdated")))
                    {
                        lastUpdated = DateTime.ParseExact(servicesNode.GetAttribute("LastUpdated"), "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                    }
                    EventViewerLog("Application", servicesNode.GetAttribute("Name"), lastUpdated);
                }
            }
            msgBuilder.Length -= 4;
            msgBuilder.Append("\n</body>\n</table>\n</br></br>\n</div>\n</br></br>\n<div id='mydiv'>\n<h3>Event Processor Monitoring</h3>\n<table id='security' border='2'>\n<tr>\n<th>Dataset</th>\n<th>Event Processor</th>\n<th>Total Process</th>\n<th>Processed</th>\n<th>Queued</th>\n</tr>");
            foreach (XmlElement environmentNode in GetXML().SelectNodes("CM_Monitor/Environments/Environment"))
            {
                foreach (XmlElement datasetNode in environmentNode.SelectNodes("Datasets/Dataset"))
                {
                    EventProcessor(datasetNode.GetAttribute("Id"), datasetNode.GetAttribute("EventLogPath"), datasetNode.GetAttribute("LastUpdated"));
                }
            }
            msgBuilder.Append("\n</table>\n</br></br>\n</div>\n</br></br>");
        }

        private static void ProcessWorkgroup(XmlElement workgroupNode, String environmentName)
        {
            msgBuilder.Append("\n<td rowspan=\"11\">" + workgroupNode.GetAttribute("Name") + "</td>\n<td rowspan=\"6\">CM Services</td>");
            log.Info("  Workgroup: " + workgroupNode.GetAttribute("Name") + ", Prop: " + workgroupNode.GetAttribute("Prop"));
            foreach (XmlElement serviceNode in workgroupNode.SelectNodes("Services/service"))
            {
                if (!String.IsNullOrEmpty(serviceNode.GetAttribute("Prop")))
                {
                    if (String.IsNullOrEmpty(serviceNode.GetAttribute("Server")))
                    {
                        CheckService(serviceNode.GetAttribute("Prop"), serviceNode.GetAttribute("Name"));
                    }
                    else
                    {
                        CheckService(serviceNode.GetAttribute("Server"), serviceNode.GetAttribute("Prop"), serviceNode.GetAttribute("Name"));
                    }
                }
                else
                {
                    msgBuilder.Append("\n</tr>\n<tr>");
                }
            }
            msgBuilder.Append("\n<td rowspan=\"5\">CM Logs</td>");
            foreach (XmlElement logPathNode in workgroupNode.SelectNodes("LogPaths/Path"))
            {
                if (!String.IsNullOrEmpty(logPathNode.GetAttribute("Path")))
                {
                    switch (logPathNode.GetAttribute("Name"))
                    {
                        case "WGSLogs":
                            CheckWGSLogs(logPathNode.GetAttribute("Path"), "WGSLogs", logPathNode.GetAttribute("LastUpdated"), environmentName, workgroupNode.GetAttribute("Name"));
                            break;
                        case "ServiceAPILogs":
                        case "WebClientLogs":
                        case "WebDrawerLogs":
                            CheckLogs(logPathNode.GetAttribute("Path"), logPathNode.GetAttribute("Name"), logPathNode.GetAttribute("LastUpdated"), environmentName, workgroupNode.GetAttribute("Name"));
                            break;
                        case "LDAPLogs":
                            CheckLDAPLogs(logPathNode.GetAttribute("Path"), "LDAPLogs", logPathNode.GetAttribute("LastUpdated"), environmentName, workgroupNode.GetAttribute("Name"));
                            break;
                        default:
                            msgBuilder.Append("\n</tr>\n<tr>");
                            break;
                    }
                }
            }
        }

        private static void ProcessDataset(XmlElement datasetNode)
        {
            msgBuilder.Append("\n<td rowspan=\"3\">" + datasetNode.GetAttribute("Name") + " : " + datasetNode.GetAttribute("Id") + "</td>");
            log.Info("  Dataset: " + datasetNode.GetAttribute("Name") + ", ID: " + datasetNode.GetAttribute("Id"));
            foreach (XmlElement urlNode in datasetNode.SelectNodes("urls/url"))
            {
                if (!String.IsNullOrEmpty(urlNode.GetAttribute("Path")))
                {
                    switch (urlNode.GetAttribute("Name"))
                    {
                        case "CMWeb":
                            CheckWebClient(urlNode.GetAttribute("Path"), "Web Client");
                            break;
                        case "CMServiceAPI":
                            CheckWebClient(urlNode.GetAttribute("Path"), "Service API");
                            break;
                        case "CMWebDrawer":
                            CheckWebClient(urlNode.GetAttribute("Path"), "Web Drawer");
                            break;
                        default:
                            msgBuilder.Append("\n</tr>\n<tr>");
                            break;
                    }
                }
            }
        }

        private static void GenerateEmailReport()
        {
            foreach (XmlElement emailNode in GetXML().SelectNodes("CM_Monitor/EmailSetup"))
            {
                if (emailNode.GetAttribute("Enabled") == "False")
                {
                    SaveHtmlReport();
                    break;
                }
                foreach (XmlElement recipientsNode in emailNode.SelectNodes("Recipients"))
                {
                    SendMail(emailNode.GetAttribute("From"), recipientsNode.GetAttribute("To"), emailNode.GetAttribute("Subject"), emailNode.GetAttribute("SmtpServer"), Convert.ToInt16(emailNode.GetAttribute("SmtpPort")));
                }
            }
        }

        private static void SaveHtmlReport()
        {
            try
            {
                String reportFolder = Path.Combine(Environment.CurrentDirectory, "Reports");
                if (!Directory.Exists(reportFolder))
                {
                    Directory.CreateDirectory(reportFolder);
                }
                String mailFile = Path.Combine(reportFolder, "EmailOutput-" + DateTime.Now.ToString("ddMMyyyyHHmmss") + ".html");
                using (StreamWriter sw = new StreamWriter(mailFile, false))
                {
                    sw.WriteLine(msgBuilder.ToString());
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        private static void CheckService(String ServiceName, String Service)
        {
            try
            {
                ServiceController sc = new ServiceController(ServiceName);
                log.Info("   CM " + Service + " Service '" + sc.ServiceName + "' is " + sc.Status);
                String color = sc.Status.ToString() != "Running" ? "Salmon" : "MediumSeaGreen";
                msgBuilder.Append("\n<td>CM " + Service + "</td>\n<td>" + sc.ServiceName + "</td>\n<td bgcolor=\"" + color + "\">" + sc.Status + "</td>\n</tr>\n<tr>");
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        private static ConnectionOptions GetConnection(String Server)
        {
            ConnectionOptions options = null;
            for (int i = 0; i < DTServer.Rows.Count; i++)
            {
                if (DTServer.Rows[i]["IP"] + "" == Server)
                {
                    options = new ConnectionOptions
                    {
                        Username = Decrypt(DTServer.Rows[i]["Username"] + "", false),
                        Password = Decrypt(DTServer.Rows[i]["Password"] + "", false),
                        Impersonation = ImpersonationLevel.Impersonate,
                        EnablePrivileges = true
                    };
                    break;
                }
            }
            return options;
        }

        private static void CheckService(String Server, String ServiceName, String Service)
        {
            ManagementScope scope = new ManagementScope("\\\\" + Server + "\\root\\cimv2", GetConnection(Server));
            try
            {
                scope.Connect();
                ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Service where Name='" + ServiceName + "'");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection services = searcher.Get();
                foreach (ManagementObject service in services)
                {
                    log.Info("   CM " + Service + " Service '" + ServiceName + "' is " + service["State"]);
                    String color = service["State"].ToString() != "Running" ? "Salmon" : "MediumSeaGreen";
                    msgBuilder.Append("\n<td>CM " + Service + "</td>\n<td>" + ServiceName + "</td>\n<td bgcolor=\"" + color + "\">" + service["State"] + "</td>\n</tr>\n<tr>");
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        private static void CheckWebClient(String URL, String Service)
        {
            int status = 0;
            X509Certificate2 cert = null;
            cert = GetSslCertificate(URL, Service, ref status);
            if (cert != null)
            {
                LogSslCertificateInfo(URL, Service, cert, ref status);
            }
            CheckUrlAvailability(URL, Service, ref status);
            String statusColor = status == 0 ? "MediumSeaGreen" : "Salmon";
            msgBuilder.Replace("statuscolor", statusColor);
        }

        private static X509Certificate2 GetSslCertificate(String url, String service, ref int status)
        {
            X509Certificate2 cert = null;
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    cert = new X509Certificate2(request.ServicePoint.Certificate);
                }
            }
            catch
            {
                cert = GetCertificateOnFailure(url, service, ref status);
            }
            return cert;
        }

        private static X509Certificate2 GetCertificateOnFailure(String url, String service, ref int status)
        {
            X509Certificate2 cert = null;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            X509Certificate rawCert = request.ServicePoint.Certificate;
            if (rawCert != null)
            {
                cert = new X509Certificate2(rawCert);
            }
            else
            {
                status = 0;
                log.Info("No SSL Certificate Available for: " + url);
                msgBuilder.Append("\n<td>" + service + "</td><td>" + url + "</td><td>" + service + "</td><td bgcolor=\"statuscolor\">No SSL Certificate Available, ");
            }
            return cert;
        }

        private static void LogSslCertificateInfo(String url, String service, X509Certificate2 cert, ref int status)
        {
            DateTime expirationDate = Convert.ToDateTime(cert.GetExpirationDateString());
            TimeSpan timeSpan = expirationDate - DateTime.Now;
            String certInfo = "SSL Certificate is valid till: " + expirationDate.ToString("yyyy-MM-dd") + " for " + url + " (" + timeSpan.Days + " Days Remaining)";
            log.Info(certInfo);
            msgBuilder.Append("\n<td>" + service + "</td>\n<td>" + url + "</td>\n<td>" + service + "</td>\n<td bgcolor=\"statuscolor\">" + certInfo + ", ");
            if (expirationDate > DateTime.Now)
            {
                status = 1;
            }
        }

        private static void CheckUrlAvailability(String url, String service, ref int status)
        {
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.UseDefaultCredentials = request.PreAuthenticate = true;
                request.Credentials = CredentialCache.DefaultCredentials;
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        log.Info("" + service + " '" + url + "' Available");
                        msgBuilder.Append("URL is Available</td>\n</tr>\n<tr>");
                    }
                    else
                    {
                        status = 1;
                        log.Info("" + service + " '" + url + "' Returned, but with status: " + response.StatusDescription);
                        msgBuilder.Append("URL Returned, but with status: " + response.StatusDescription + "</td>\n</tr>\n<tr>");
                    }
                }
            }
            catch (Exception ex)
            {
                status = 1;
                log.Error(service + " '" + url + "' unavailable: " + ex);
                msgBuilder.Append("URL is Unavailable</td>\n</tr>\n<tr>");
            }
        }

        private static DataTable InitializeDataTable()
        {
            DataTable dt = new DataTable();
            dt.Columns.Add("First_Occurrence");
            dt.Columns.Add("Last_Occurrence");
            dt.Columns.Add("Error");
            dt.Columns.Add("Count");
            return dt;
        }

        private static void CheckLogs(String path, String Service, String time, String Environment, String WGS)
        {
            try
            {
                DataTable dt = InitializeDataTable();
                List<String[]> rows = new List<String[]>();
                DateTime last = DateTime.Now;
                if (Directory.Exists(path))
                {
                    DirectoryInfo folder = new DirectoryInfo(path);
                    var files = folder.GetFiles().Where(file => file.Name.Equals("log-file.txt", StringComparison.OrdinalIgnoreCase) && file.LastWriteTime < last);
                    if (!String.IsNullOrEmpty(time))
                    {
                        last = DateTime.ParseExact(time, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                        files = folder.GetFiles().Where(file => file.Name.Equals("log-file.txt", StringComparison.OrdinalIgnoreCase) && file.LastWriteTime > last);
                    }
                    object dtLock = new object();
                    object rowsLock = new object();
                    Parallel.ForEach(files, file =>
                    {
                        using (FileStream fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (StreamReader sr = new StreamReader(fs, Encoding.Default))
                        {
                            String logLines = sr.ReadToEnd();
                            Regex pattern = new Regex(@"^(?<Timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\,\d{3})\s\[(?<ThreadId>\d+)\]\s(?<LogLevel>\w+)\s(?<ErrorMessage>.+)$", RegexOptions.Multiline | RegexOptions.Compiled);
                            List<LogEntry> logEntries = new List<LogEntry>();
                            var matches = pattern.Matches(logLines);
                            foreach (Match match in matches)
                            {
                                LogEntry logEntry = new LogEntry
                                {
                                    Timestamp = DateTime.ParseExact(match.Groups["Timestamp"].Value, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture),
                                    ThreadId = match.Groups["ThreadId"].Value,
                                    LogLevel = match.Groups["LogLevel"].Value,
                                    ErrorMessage = match.Groups["ErrorMessage"].Value
                                };
                                if (logEntry.LogLevel == "ERROR")
                                {
                                    if (!String.IsNullOrEmpty(time))
                                    {
                                        DateTime lastupdated = DateTime.ParseExact(time, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                                        if (logEntry.Timestamp < lastupdated)
                                        {
                                            continue;
                                        }
                                    }
                                    logEntries.Add(logEntry);
                                }
                            }
                            lock (dtLock)
                            {
                                foreach (var entry in logEntries)
                                {
                                    log.Info("Timestamp: " + entry.Timestamp + ", ThreadId: " + entry.ThreadId + ", LogLevel: " + entry.LogLevel + ", ErrorMessage: " + entry.ErrorMessage.Trim());
                                    String[] row = { entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), Environment, WGS, "", entry.ThreadId, entry.LogLevel, entry.ErrorMessage.Trim() };
                                    lock (rowsLock)
                                    {
                                        rows.Add(row);
                                    }
                                    int flag = 0;
                                    for (int i = 0; i < dt.Rows.Count; i++)
                                    {
                                        if (dt.Rows[i][2].ToString() == entry.ErrorMessage.Trim())
                                        {
                                            DateTime first = DateTime.ParseExact(dt.Rows[i][0] + "", "dd-MM-yyyy HH:mm:ss.fff", CultureInfo.InvariantCulture);
                                            if (first > entry.Timestamp)
                                            {
                                                dt.Rows[i][0] = entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                            }
                                            else
                                            {
                                                dt.Rows[i][1] = entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                            }
                                            int count = int.Parse(dt.Rows[i][3] + "");
                                            dt.Rows[i][3] = count + 1;
                                            flag = 1;
                                            break;
                                        }
                                    }
                                    if (flag == 0)
                                    {
                                        dt.Rows.Add(entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.ErrorMessage.Trim(), 1);
                                    }
                                }
                            }
                        }
                    });
                    UpdateXML(Service, Environment, WGS, rows, dt);
                    String color = rows.Count == 0 ? "MediumSeaGreen" : "Salmon";
                    msgBuilder.Append("\n<td>" + Service + "</td>\n<td>" + Service + "</td>\n<td bgcolor=\"" + color + "\">" + rows.Count + " Errors Found, " + last.ToString("yyyy-MM-dd HH:mm:ss,fff") + "</td>\n</tr>\n<tr>");
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        private static void CheckWGSLogs(String path, String Service, String time, String Environment, String WGS)
        {
            try
            {
                DataTable dt = InitializeDataTable();
                List<String[]> rows = new List<String[]>();
                DateTime last = DateTime.Now;
                if (Directory.Exists(path))
                {
                    DirectoryInfo folder = new DirectoryInfo(path);
                    var files = folder.GetFiles().Where(file => file.Name.StartsWith("TRIMWorkgroup") && file.LastWriteTime < last && file.Extension == ".log");
                    if (!String.IsNullOrEmpty(time))
                    {
                        last = DateTime.ParseExact(time, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                        files = folder.GetFiles().Where(file => file.Name.StartsWith("TRIMWorkgroup") && file.LastWriteTime > last && file.Extension == ".log");
                    }
                    object dtLock = new object();
                    object rowsLock = new object();
                    Parallel.ForEach(files, file =>
                    {
                        using (FileStream fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (StreamReader sr = new StreamReader(fs, Encoding.Default))
                        {
                            String logLines = sr.ReadToEnd();
                            Regex pattern = new Regex(@"^(?<Timestamp>\d{2}:\d{2}:\d{2}:\d{3})\s+(?<ThreadId>\d+)\s+(?<Dataset>\w+)\s+(?<UnknownField>\d+)\s+(?<UnknownField2>\d+)\s+(?<LogLevel>\w+):\s+(?<ErrorMessage>.+)$", RegexOptions.Multiline | RegexOptions.Compiled);
                            List<LogEntry> logEntries = new List<LogEntry>();
                            var matches = pattern.Matches(logLines);
                            foreach (Match match in matches)
                            {
                                LogEntry logEntry = new LogEntry
                                {
                                    Timestamp = DateTime.ParseExact(file.CreationTime.ToString("yyyy-MM-dd") + " " + match.Groups["Timestamp"].Value, "yyyy-MM-dd HH:mm:ss:fff", CultureInfo.InvariantCulture),
                                    Dataset = match.Groups["Dataset"].Value,
                                    ThreadId = match.Groups["ThreadId"].Value,
                                    LogLevel = match.Groups["LogLevel"].Value,
                                    ErrorMessage = match.Groups["ErrorMessage"].Value
                                };
                                if (logEntry.LogLevel == "Error")
                                {
                                    if (!String.IsNullOrEmpty(time))
                                    {
                                        DateTime lastupdated = DateTime.ParseExact(time, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                                        if (logEntry.Timestamp < lastupdated)
                                        {
                                            continue;
                                        }
                                    }
                                    logEntries.Add(logEntry);
                                }
                            }
                            lock (dtLock)
                            {
                                foreach (var entry in logEntries)
                                {
                                    log.Info(" Timestamp = " + file.LastWriteTime.ToString("yyyy-MM-dd") + " " + entry.Timestamp.ToString("HH:mm:ss,fff") + ", Dataset = " + entry.Dataset + ", ThreadId = " + entry.ThreadId + ", LogLevel = " + entry.LogLevel + ", ErrorMessage = " + entry.ErrorMessage.Trim());
                                    String[] row = { entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), Environment, WGS, entry.Dataset, entry.ThreadId, entry.LogLevel, entry.ErrorMessage.Trim() };
                                    lock (rowsLock)
                                    {
                                        rows.Add(row);
                                    }
                                    int flag = 0;
                                    for (int i = 0; i < dt.Rows.Count; i++)
                                    {
                                        if (dt.Rows[i][2].ToString() == entry.ErrorMessage.Trim())
                                        {
                                            DateTime first = DateTime.ParseExact(dt.Rows[i][0] + "", "dd-MM-yyyy HH:mm:ss.fff", CultureInfo.InvariantCulture);
                                            if (first > entry.Timestamp)
                                            {
                                                dt.Rows[i][0] = entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                            }
                                            else
                                            {
                                                dt.Rows[i][1] = entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                            }
                                            int count = int.Parse(dt.Rows[i][3] + "");
                                            dt.Rows[i][3] = count + 1;
                                            flag = 1;
                                            break;
                                        }
                                    }
                                    if (flag == 0)
                                    {
                                        dt.Rows.Add(entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.ErrorMessage.Trim(), 1);
                                    }
                                }
                            }
                        }
                    });
                    String color = rows.Count == 0 ? "MediumSeaGreen" : "Salmon";
                    msgBuilder.Append("\n<td>" + Service + "</td>\n<td>" + Service + "</td>\n<td bgcolor=\"" + color + "\">" + rows.Count + " Errors Found, " + last.ToString("yyyy-MM-dd HH:mm:ss,fff") + "</td>\n</tr>\n<tr>");
                    UpdateXML(Service, Environment, WGS, rows, dt);
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        private static void EventViewerLog(String logName, String sourceName, DateTime lastdate)
        {
            try
            {
                DataTable dt = InitializeDataTable();
                List<String[]> rows = new List<String[]>();
                EventLog eventLog = new EventLog(logName);
                object dtLock = new object();
                object rowsLock = new object();
                Parallel.ForEach(eventLog.Entries.Cast<EventLogEntry>(), entry =>
                {
                    if (entry.Source.Equals(sourceName, StringComparison.OrdinalIgnoreCase) && entry.EntryType == EventLogEntryType.Error && entry.TimeGenerated >= lastdate)
                    {
                        log.Info("Event ID : " + entry.InstanceId + "\t Entry Type: " + entry.EntryType + "\t Source : " + entry.Source + "\t Message: " + entry.Message.Replace("\r\n", " : ") + "\t Time Generated: " + entry.TimeGenerated);
                        String[] row = { entry.TimeGenerated.ToString("dd-MM-yyyy HH:mm:ss.fff"), "Event Viewer", "", entry.Source, entry.InstanceId + "", entry.EntryType + "", entry.Message.Replace("\r\n", " : ") };
                        lock (rowsLock)
                        {
                            rows.Add(row);
                        }
                        lock (dtLock)
                        {
                            int flag = 0;
                            for (int i = 0; i < dt.Rows.Count; i++)
                            {
                                if (dt.Rows[i][2].ToString() == entry.Message.Replace("\r\n", " : "))
                                {
                                    DateTime first = DateTime.ParseExact(dt.Rows[i][0] + "", "dd-MM-yyyy HH:mm:ss.fff", CultureInfo.InvariantCulture);
                                    if (first > entry.TimeGenerated)
                                    {
                                        dt.Rows[i][0] = entry.TimeGenerated.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                    }
                                    else
                                    {
                                        dt.Rows[i][1] = entry.TimeGenerated.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                    }
                                    int count = int.Parse(dt.Rows[i][3] + "");
                                    dt.Rows[i][3] = count + 1;
                                    flag = 1;
                                    break;
                                }
                            }
                            if (flag == 0)
                            {
                                dt.Rows.Add(entry.TimeGenerated.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.TimeGenerated.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.Message.Replace("\r\n", " : "), 1);
                            }
                        }
                    }
                });
                String color = rows.Count == 0 ? "MediumSeaGreen" : "Salmon";
                msgBuilder.Append("\n<td></td>\n<td></td>\n<td>Event Viewer Logs</td>\n<td>" + sourceName + "</td>\n<td>Windows Event Logs</td>\n<td bgcolor=\"" + color + "\">" + rows.Count + " Errors Found, " + lastdate.ToString("dd-MM-yyyy HH:mm:ss.fff") + "</td>\n</tr>\n<tr>");
                XDocument xmlDoc = XDocument.Load("CM_Monitor.xml");
                var target = xmlDoc.Elements("Root").Elements("CM_Monitor").Elements("WindowsEvent").Elements("Services").Where(e => e.Attribute("Name").Value == sourceName).Single();
                target.Attribute("LastUpdated").Value = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss,fff");
                xmlDoc.Save("CM_Monitor.xml");
                UpdateXML("", "", "", rows, dt);
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        private static void CheckLDAPLogs(String path, String Service, String time, String Environment, String WGS)
        {
            try
            {
                DataTable dt = InitializeDataTable();
                List<String[]> rows = new List<String[]>();
                DateTime last = DateTime.Now;
                if (Directory.Exists(path))
                {
                    DirectoryInfo folder = new DirectoryInfo(path);
                    var files = folder.GetFiles().Where(file => file.LastWriteTime < last);
                    if (!String.IsNullOrEmpty(time))
                    {
                        last = DateTime.ParseExact(time, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                        files = folder.GetFiles().Where(file => file.LastWriteTime > last);
                    }
                    object dtLock = new object();
                    object rowsLock = new object();
                    Parallel.ForEach(files, file =>
                    {
                        using (FileStream fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (StreamReader sr = new StreamReader(fs, Encoding.Default))
                        {
                            String logLines = sr.ReadToEnd();
                            Regex pattern = new Regex(@"^(?<Timestamp>\d{2}:\d{2}:\d{2}:\d{3})\s+(?<ThreadId>\d+)\s+(?<LogLevel>--|-\w+-|-\w+-|\*)\s+(?<ErrorMessage>.+)$", RegexOptions.Multiline | RegexOptions.Compiled);
                            List<LogEntry> logEntries = new List<LogEntry>();
                            var matches = pattern.Matches(logLines);
                            foreach (Match match in matches)
                            {
                                LogEntry logEntry = new LogEntry
                                {
                                    Timestamp = DateTime.ParseExact(file.CreationTime.ToString("yyyy-MM-dd") + " " + match.Groups["Timestamp"].Value, "yyyy-MM-dd HH:mm:ss:fff", CultureInfo.InvariantCulture),
                                    ThreadId = match.Groups["ThreadId"].Value,
                                    LogLevel = match.Groups["LogLevel"].Value,
                                    ErrorMessage = match.Groups["ErrorMessage"].Value
                                };
                                if (logEntry.ErrorMessage.StartsWith("Failed"))
                                {
                                    if (!String.IsNullOrEmpty(time))
                                    {
                                        DateTime lastupdated = DateTime.ParseExact(time, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                                        if (logEntry.Timestamp < lastupdated)
                                        {
                                            continue;
                                        }
                                    }
                                    logEntries.Add(logEntry);
                                }
                            }
                            foreach (var entry in logEntries)
                            {
                                log.Info(" Timestamp = " + file.LastWriteTime.ToString("yyyy-MM-dd") + " " + entry.Timestamp.ToString("HH:mm:ss,fff") + ", Dataset = " + entry.Dataset + ", ThreadId = " + entry.ThreadId + ", LogLevel = " + entry.LogLevel + ", ErrorMessage = " + entry.ErrorMessage.Trim());
                                String[] row = { entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), Environment, WGS, entry.Dataset, entry.ThreadId, entry.LogLevel, entry.ErrorMessage.Trim() };
                                lock (rowsLock)
                                {
                                    rows.Add(row);
                                }
                                lock (dtLock)
                                {
                                    int flag = 0;
                                    for (int i = 0; i < dt.Rows.Count; i++)
                                    {
                                        if (dt.Rows[i][2].ToString() == entry.ErrorMessage.Trim())
                                        {
                                            DateTime first = DateTime.ParseExact(dt.Rows[i][0].ToString(), "dd-MM-yyyy HH:mm:ss.fff", CultureInfo.InvariantCulture);
                                            if (first > entry.Timestamp)
                                            {
                                                dt.Rows[i][0] = entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                            }
                                            else
                                            {
                                                dt.Rows[i][1] = entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                            }
                                            int count = int.Parse(dt.Rows[i][3].ToString());
                                            dt.Rows[i][3] = count + 1;
                                            flag = 1;
                                            break;
                                        }
                                    }
                                    if (flag == 0)
                                    {
                                        dt.Rows.Add(entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.ErrorMessage.Trim(), 1);
                                    }
                                }
                            }
                        }
                    });
                    String color = rows.Count == 0 ? "MediumSeaGreen" : "Salmon";
                    msgBuilder.Append("\n<td>" + Service + "</td>\n<td>" + Service + "</td>\n<td bgcolor=\"" + color + "\">" + rows.Count + " Errors Found, " + last.ToString("yyyy-MM-dd HH:mm:ss,fff") + "</td>\n</tr>\n<tr>");
                    UpdateXML(Service, Environment, WGS, rows, dt);
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        private static void EventProcessor(String Dataset, String LogPath, String time)
        {
            try
            {
                DateTime last = DateTime.Now;
                if (Directory.Exists(LogPath))
                {
                    DirectoryInfo folder = new DirectoryInfo(LogPath);
                    var files = folder.GetFiles().Where(file => file.LastWriteTime < last && file.Name.StartsWith("TRIMEvent_" + Dataset + "_"));
                    if (!String.IsNullOrEmpty(time))
                    {
                        last = DateTime.ParseExact(time, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                        files = folder.GetFiles().Where(file => file.LastWriteTime > last && file.Name.StartsWith("TRIMEvent_" + Dataset + "_"));
                    }
                    var eventEntries = new ConcurrentDictionary<String, EventEntry>();
                    Regex addedRegex = new Regex(@"^(?<Timestamp>\d{2}:\d{2}:\d{2}:\d{3})\s+(?<ThreadId>\d+)\s+(?<Dataset>\w+)\s+(?<Event>.+)(: \(workgroup notification\)) : Received (?<Count>\d+).+$", RegexOptions.Multiline | RegexOptions.Compiled);
                    Regex processedRegex = new Regex(@"^(?<Timestamp>\d{2}:\d{2}:\d{2}:\d{3})\s+(?<ThreadId>\d+)\s+(?<Dataset>\w+)\s+(?<Event>.+):\s+(?<Data>processing event: \d+, eventtype =\d+, bobtype=\d+, boburi=\d+, event processed immediatel).+$", RegexOptions.Multiline | RegexOptions.Compiled);
                    Regex processedBufferRegex = new Regex(@"^(?<Timestamp>\d{2}:\d{2}:\d{2}:\d{3})\s+(?<ThreadId>\d+)\s+(?<Dataset>\w+)\s+(?<Event>.+):\s+(?<Data>processing )(?<Count>\d+)(?<Buffer> buffered event).+$", RegexOptions.Multiline | RegexOptions.Compiled);
                    Parallel.ForEach(files, file =>
                    {
                        using (FileStream fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (StreamReader sr = new StreamReader(fs, Encoding.Default))
                        {
                            String logLines = sr.ReadToEnd();
                            ProcessLogLines(logLines, addedRegex, eventEntries, "Total", match => Convert.ToInt32(match.Groups["Count"].Value));
                            ProcessLogLines(logLines, processedRegex, eventEntries, "Processed", match => 1);
                            ProcessLogLines(logLines, processedBufferRegex, eventEntries, "Processed", match => Convert.ToInt32(match.Groups["Count"].Value));
                        }
                    });
                    msgBuilder.Append("\n<tr>\n<td rowspan=\"" + eventEntries.Count + "\">" + Dataset + "</td>");
                    foreach (var entry in eventEntries.Values)
                    {
                        msgBuilder.Append("\n<td>" + entry.Event + "</td>\n<td>" + entry.Total + "</td>\n<td>" + entry.Processed + "</td>\n<td>" + (entry.Total - entry.Processed) + "</td>\n</tr>");
                    }
                    XDocument xmlDoc = XDocument.Load("CM_Monitor.xml");
                    var target = xmlDoc.Elements("Root").Elements("CM_Monitor").Elements("Environments").Elements("Environment").Elements("Datasets").Elements("Dataset").Where(e => e.Attribute("Id").Value == Dataset).Single();
                    target.Attribute("LastUpdated").Value = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss,fff");
                    xmlDoc.Save("CM_Monitor.xml");
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        private static void ProcessLogLines(String logLines, Regex regex, ConcurrentDictionary<String, EventEntry> eventEntries, String field, Func<Match, int> valueSelector)
        {
            var matches = regex.Matches(logLines);
            foreach (Match match in matches)
            {
                String eventName = match.Groups["Event"].Value;
                eventEntries.AddOrUpdate(eventName, _ => new EventEntry
                {
                    Event = eventName,
                    Total = field == "Total" ? valueSelector(match) : 0,
                    Processed = field == "Processed" ? valueSelector(match) : 0
                },
                    (_, entry) =>
                    {
                        if (field == "Total")
                        {
                            entry.Total += valueSelector(match);
                        }
                        else if (field == "Processed")
                        {
                            entry.Processed += valueSelector(match);
                        }
                        return entry;
                    });
            }
        }

        private static void UpdateXML(String Service, String Environment, String WGS, List<String[]> rows, DataTable dt)
        {
            try
            {
                if (Service != "" && Environment != "" && WGS != "")
                {
                    XDocument xmlDoc = XDocument.Load("CM_Monitor.xml");
                    var target = xmlDoc.Elements("Root").Elements("CM_Monitor").Elements("Environments").Elements("Environment").Where(e => e.Attribute("Name").Value == Environment).Elements("WorkgroupServers").Elements("Workgroup").Where(e => e.Attribute("Name").Value == WGS).Elements("LogPaths").Elements("Path").Where(e => e.Attribute("Name").Value == Service).Single();
                    target.Attribute("LastUpdated").Value = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss,fff");
                    xmlDoc.Save("CM_Monitor.xml");
                }
                String csvFilePath = "Logs\\Detaliedlog-" + DateTime.Now.ToString("ddMMyyyy") + ".csv";
                using (StreamWriter writer = new StreamWriter(csvFilePath, true))
                {
                    if (new FileInfo(csvFilePath).Length == 0)
                    {
                        writer.WriteLine("Timestamp,Environment,WorkGroup Server,Dataset,Thread Id,Log Level,Error Message");
                    }
                    foreach (var row in rows)
                    {
                        writer.WriteLine(String.Join(",", row));
                    }
                }
                String filepath = "Logs\\Errorlog-" + DateTime.Now.ToString("ddMMyyyy") + ".csv";
                StringBuilder csvContent = new StringBuilder();
                if (!File.Exists(filepath))
                {
                    csvContent.AppendLine(String.Join(",", dt.Columns.Cast<DataColumn>().Select(col => col.ColumnName)));
                }
                foreach (DataRow row in dt.Rows)
                {
                    csvContent.AppendLine(String.Join(",", row.ItemArray.Select(field => QuoteIfNeeded(field + ""))));
                }
                File.AppendAllText(filepath, csvContent + "");
                log.Info("CSV Conversion Completed.");
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        private static String QuoteIfNeeded(String value)
        {
            if (value.Contains(",") || value.Contains("\"") || value.Contains("\r") || value.Contains("\n"))
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }
            else
            {
                return value;
            }
        }

        private static void GetCpuDetails()
        {
            try
            {
                String local = "Local";
                foreach (XmlElement serverDetails in GetXML().SelectNodes("CM_Monitor/Environments/Environment"))
                {
                    local = serverDetails.GetAttribute("Name");
                }
                log.Info(local + " CPU Details : ");
                decimal clockspeed = 0;
                PerformanceCounter cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                PerformanceCounter ramCounter = new PerformanceCounter("Memory", "Available MBytes");
                cpuCounter.NextValue();
                Thread.Sleep(1000);
                log.Info("CPU Usage: " + cpuCounter.NextValue().ToString("0") + "%");
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher("select CurrentClockSpeed from Win32_Processor"))
                {
                    foreach (ManagementObject mo in mos.Get())
                    {
                        clockspeed = Convert.ToDecimal(mo["CurrentClockSpeed"]) / 1000;
                        log.Info("Current Clock Speed: " + clockspeed.ToString("0.##") + " GHz");
                    }
                    log.Info("Total Memory: " + GetTotalMemoryInMB() + " MB");
                    log.Info("Used Memory: " + (GetTotalMemoryInMB() - ramCounter.NextValue()) + " MB");
                    log.Info("Available Memory: " + ramCounter.NextValue() + " MB");
                }
                msgBuilder.Append("\n<div id='mydiv'>\n<h3>System Monitoring</h3>\n<table id='security' border='2'>\n<tr>\n<th>Server</th>\n<th>CPU/Drives</th>\n<th>Total</th>\n<th>Used</th>\n<th>Available</th>\n</tr>\n<tr>\n<td rowspan=\"drivecount\">" + local + "</td>\n<td>Utilization - " + cpuCounter.NextValue().ToString("0") + "% - " + clockspeed.ToString("0.##") + " GHz</td>\n<td>RAM : " + GetTotalMemoryInMB() + " MB</td>\n<td>RAM : " + (GetTotalMemoryInMB() - ramCounter.NextValue()) + " MB</td>\n<td>RAM : " + ramCounter.NextValue() + " MB</td>\n</tr>");
                int drivecount = 1;
                DriveInfo[] drives = DriveInfo.GetDrives();
                foreach (DriveInfo drive in drives)
                {
                    if (drive.IsReady && drive.TotalSize > 0)
                    {
                        decimal total = (decimal)drive.TotalSize / (1024 * 1024 * 1024);
                        decimal available = (decimal)drive.AvailableFreeSpace / (1024 * 1024 * 1024);
                        decimal used = total - available;
                        log.Info("Drive Name: " + drive.Name);
                        log.Info("Volume Label: " + drive.VolumeLabel);
                        log.Info("Total Size: " + total.ToString("0.##") + " GB");
                        log.Info("Used Size: " + used.ToString("0.##") + " GB - " + ((used * 100) / total).ToString("0.##") + "%");
                        log.Info("Available Size: " + available.ToString("0.##") + " GB - " + ((available * 100) / total).ToString("0.##") + "%");
                        msgBuilder.AppendLine("\n<tr>\n<td>" + drive.VolumeLabel + " - " + drive.Name + "</td>\n<td>Size : " + total.ToString("0.##") + " GB</td>\n<td>Size : " + used.ToString("0.##") + " GB - " + ((used * 100) / total).ToString("0.##") + "%</td>\n<td>Size : " + available.ToString("0.##") + " GB - " + ((available * 100) / total).ToString("0.##") + "%</td>\n</tr>");
                        drivecount += 1;
                    }
                }
                msgBuilder.Replace("drivecount", drivecount + "");
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        private static void GetCpuDetails(String Server)
        {
            try
            {
                log.Info(Server + " CPU Details :");
                decimal clockspeed = 0, clockper = 0;
                ManagementScope scope = new ManagementScope("\\\\" + Server + "\\root\\cimv2", GetConnection(Server));
                scope.Connect();
                ObjectQuery query = new ObjectQuery("SELECT CurrentClockSpeed, LoadPercentage FROM Win32_Processor");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
                {
                    foreach (ManagementObject mo in searcher.Get())
                    {
                        log.Info("CPU Usage: " + (Convert.ToDecimal(mo["LoadPercentage"])).ToString("0") + "%");
                        log.Info("Current Clock Speed: " + (Convert.ToDecimal(mo["CurrentClockSpeed"]) / 1000).ToString("0.##") + " GHz");
                        break;
                    }
                }
                query = new ObjectQuery("SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
                {
                    foreach (ManagementObject mo in searcher.Get())
                    {
                        ulong totalMemory = (ulong)mo["TotalVisibleMemorySize"];
                        ulong freeMemory = (ulong)mo["FreePhysicalMemory"];
                        ulong usedMemory = totalMemory - freeMemory;
                        log.Info("Total Memory: " + totalMemory / 1024 + " MB");
                        log.Info("Used Memory: " + usedMemory / 1024 + " MB");
                        log.Info("Available Memory: " + freeMemory / 1024 + " MB");
                        msgBuilder.Append("\n<tr>\n<td rowspan=\"drivecount\">" + Server + "</td>\n<td>Utilization - " + clockper.ToString("0") + "% - " + clockspeed.ToString("0.##") + " GHz</td>\n<td>RAM : " + totalMemory / 1024 + " MB</td>\n<td>RAM : " + usedMemory / 1024 + " MB</td>\n<td>RAM : " + freeMemory / 1024 + " MB</td>\n</tr>");
                    }
                }
                int drivecount = 1;
                query = new ObjectQuery("SELECT DeviceID, FreeSpace, Size, VolumeName FROM Win32_LogicalDisk");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
                {
                    foreach (ManagementObject mo in searcher.Get())
                    {
                        if (Convert.ToDecimal(mo["Size"]) > 0)
                        {
                            decimal total = Convert.ToDecimal((Convert.ToDecimal(mo["Size"]) / (1024 * 1024 * 1024)).ToString("0.##"));
                            decimal available = Convert.ToDecimal((Convert.ToDecimal(mo["FreeSpace"]) / (1024 * 1024 * 1024)).ToString("0.##"));
                            decimal used = total - available;
                            log.Info("Drive Name: " + mo["DeviceID"]);
                            log.Info("Volume Name: " + mo["VolumeName"]);
                            log.Info("Total Size: " + total + " GB");
                            log.Info("Used Size: " + used + " GB- " + ((used * 100) / total).ToString("0.##") + "%");
                            log.Info("Available Space: " + available + " GB- " + ((available * 100) / total).ToString("0.##") + "%");
                            msgBuilder.AppendLine("\n<tr>\n<td>" + mo["VolumeName"] + " - " + mo["DeviceID"] + "\\</td>\n<td>Size : " + total.ToString("0.##") + " GB</td>\n<td>Size : " + used.ToString("0.##") + " GB - " + ((used * 100) / total).ToString("0.##") + "%</td>\n<td>Size : " + available.ToString("0.##") + " GB - " + ((available * 100) / total).ToString("0.##") + "%</td>\n</tr>");
                            drivecount += 1;
                        }
                    }
                }
                msgBuilder.Replace("drivecount", drivecount + "");
                msgBuilder.AppendLine("\n</table>\n</br></br></div>\n</br></br>");
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        private static ulong GetTotalMemoryInMB()
        {
            using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem"))
            {
                foreach (ManagementObject mo in mos.Get())
                {
                    return Convert.ToUInt64(mo["TotalPhysicalMemory"]) / (1024 * 1024);
                }
            }
            return 0;
        }

        private static void SendMail(String From, String To, String Subject, String SmtpServer, int SmtpPort)
        {
            try
            {
                using (MailMessage mail = new MailMessage(From, To, Subject, msgBuilder.ToString()))
                {
                    mail.IsBodyHtml = true;
                    mail.Attachments.Add(new Attachment("Logs\\Errorlog-" + DateTime.Now.ToString("ddMMyyyy") + ".csv"));
                    mail.Attachments.Add(new Attachment("Logs\\Detaliedlog-" + DateTime.Now.ToString("ddMMyyyy") + ".csv"));
                    SmtpClient smtpClient = new SmtpClient(SmtpServer, SmtpPort);
                    smtpClient.EnableSsl = false;
                    smtpClient.Send(mail);
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        private static void DeleteLogFiles()
        {
            String[] files = Directory.GetFiles("Logs\\");
            foreach (String file in files)
            {
                try
                {
                    TimeSpan age = DateTime.Now - File.GetLastWriteTime(file);
                    if (age.TotalDays > 30)
                    {
                        File.Delete(file);
                        Console.WriteLine("Deleted: " + file);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error deleting file " + file + ": " + ex);
                }
            }
        }

        private static String Decrypt(String cipherString, bool useHashing)
        {
            byte[] keyArray;
            byte[] toEncryptArray = Convert.FromBase64String(cipherString);
            String key = "WETHEPEOPLEOFINDIAHAVING";
            if (useHashing)
            {
                using (SHA256CryptoServiceProvider hashSha256 = new SHA256CryptoServiceProvider())
                {
                    keyArray = hashSha256.ComputeHash(Encoding.UTF8.GetBytes(key));
                }
            }
            else
            {
                keyArray = Encoding.UTF8.GetBytes(key);
            }
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Key = keyArray;
                tdes.Mode = CipherMode.ECB;
                ICryptoTransform cTransform = tdes.CreateDecryptor();
                byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
                return Encoding.UTF8.GetString(resultArray);
            }
        }
    }
}