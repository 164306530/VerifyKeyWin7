using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Win32;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Xml;
using System.Web;

namespace PidKey
{
    class PidGen
    {
        static string  Dir = Path.GetTempPath();


      
        [DllImport(@"C:\Windows\PidGenX32.dll", EntryPoint = "PidGenX", ExactSpelling = false, CharSet = CharSet.Unicode)]
        static extern int PidGenX32(string WindowsKey, string PkeyPath, string MPCID, int UnknownUsage, IntPtr GeneratedProductID, IntPtr OldDigitalProductID, IntPtr DigitalProductID);
        [DllImport("pidgenx.dll", EntryPoint = "PidGenX", CharSet = CharSet.Auto)]
        static extern int PidGenX(string ProductKey, string PkeyPath, string MSPID, int UnknownUsage, IntPtr ProductID, IntPtr DigitalProductID, IntPtr DigitalProductID4);

        [DllImport(@"C:\Windows\PidGenX64.dll", EntryPoint = "PidGenX", ExactSpelling = false, CharSet = CharSet.Unicode)]
        static extern int PidGenX64(string WindowsKey, string PkeyPath, string MPCID, int UnknownUsage, IntPtr GeneratedProductID, IntPtr OldDigitalProductID, IntPtr DigitalProductID);
        //static extern int PidGenX(string ProductKey, string PkeyPath, string MSPID, int UnknownUsage, IntPtr ProductID, IntPtr DigitalProductID, IntPtr DigitalProductID4);
        public static int CheckPidKey(string Key, out string pkeyconfig, string MPCID, int UnknownUsage, IntPtr genPID, IntPtr oldPID, IntPtr DPID4)
        {

            int RetID = -1;

            if (!System.IO.Directory.Exists(Dir + @"\pkconfig"))
            {
                pkeyconfig="";
                return -1;
            }
            else
            {
                pkeyconfig = Environment.GetFolderPath(Environment.SpecialFolder.System) + @"\spp\tokens\pkeyconfig\pkeyconfig.xrm-ms";
                RetID = CallPidGenX(Key, pkeyconfig, "XXXXX",0, genPID,oldPID, DPID4);
                if (RetID != 0)
                {
                    foreach (var filePath in Directory.GetFiles(Dir + @"\pkconfig", "*.*", SearchOption.AllDirectories))
                    {
                        RetID = CallPidGenX(Key, filePath, "XXXXX", 0, genPID, oldPID, DPID4);
                        if (RetID == 0)
                        {
                            pkeyconfig = filePath; break;
                        }
                    }
                }
            }
            // ProductID = genPID

            return RetID;
        }
        public static int CallPidGenX(string Key, string pkeyconfig, string MPCID, int UnknownUsage, IntPtr genPID, IntPtr oldPID, IntPtr DPID4)
        {
            int RetID;
            if (System.Environment.OSVersion.Version.ToString().Contains("Windows 7"))
            {
                var systemOsType =(string) Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "PROCESSOR_ARCHITECTURE", "Key does Not exist");
                if (systemOsType == "x86")
                {
                    if (File.Exists(@"C:\Windows\pidgenx32.dll"))
                        RetID = PidGenX32(Key, pkeyconfig, "XXXXX", 0, genPID, oldPID, DPID4);
                    else
                        RetID = PidGenX(Key, pkeyconfig, "XXXXX", 0, genPID, oldPID, DPID4);
                }
                else if (File.Exists(@"C:\Windows\pidgenx64.dll"))
                    RetID = PidGenX64(Key, pkeyconfig, "XXXXX", 0, genPID, oldPID, DPID4);
                else
                    RetID = PidGenX(Key, pkeyconfig, "XXXXX", 0, genPID, oldPID, DPID4);
            }
            else
                RetID = PidGenX(Key, pkeyconfig, "XXXXX", 0, genPID, oldPID, DPID4);
            return RetID;
        }

        /// <summary>
        /// Gets the Product Description
        /// </summary>
        /// <param name="pkey">path to PkeyConfig.xrm-ms file</param>
        /// <param name="aid">Activation ID</param>
        /// <param name="edi">Edition ID</param>
        /// <returns>Product Description</returns>
        static string GetProductDescription(string pkey, string aid, string edi)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(pkey);
            MemoryStream stream = new MemoryStream(Convert.FromBase64String(doc.GetElementsByTagName("tm:infoBin")[0].InnerText));
            doc.Load(stream);
            XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("pkc", "http://www.microsoft.com/DRM/PKEY/Configuration/2.0");
            try
            {
                XmlNode node = doc.SelectSingleNode("/pkc:ProductKeyConfiguration/pkc:Configurations/pkc:Configuration[pkc:ActConfigId='" + aid + "']", ns);
                if (node == null)
                {
                    node = doc.SelectSingleNode("/pkc:ProductKeyConfiguration/pkc:Configurations/pkc:Configuration[pkc:ActConfigId='" + aid.ToUpper() + "']", ns);
                }
                if (node.HasChildNodes)
                {
                    if (node.ChildNodes[2].InnerText.Contains(edi))
                    {
                        return node.ChildNodes[3].InnerText;
                    }
                    return "Not Found";
                }
                return "Not Found";
            }
            catch (Exception)
            {
                return "Not Found";
            }
            finally
            {
                stream.Dispose();
            }
        }
        public static string GetErrorCoder(string pid)
        {

            string requestXml = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\"><soap:Body><RequestSecurityToken xmlns=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\"><TokenType>ProductActivation</TokenType><RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</RequestType><UseKey><Values xmlns:q1=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\" soapenc:arrayType=\"q1:TokenEntry[1]\"><TokenEntry><Name>PublishLicense</Name><Value>vrNNhbj1hD/h5icdZtSgcoJYReJaRC81irn7XSnvoqbt4V4ARKDfzhYivpi0UZ64Rds5E1dUhqXp+s+Kf/9aTT0xvUmzEj4m6ZJdPXrfy8fqfhf/pLI5hlisJvQrjtIeIwjzMseF/yQre0XgWOTFByhozoRUX3+85tcFC6i8EerRn218IUkesERj8u7t7dAIQMfmNjjRvnMV5+jlujWvJLtpNjW64/ZTuVeiD1+wlXAZNncJB5xUk8klvKBDtfREolM8Z7npRIxkVAXn6PZlT4zMWqJpMX3b4DI60qu41+G+6YvYE2YbTHMiop3bRdyk6fRDLwSaQ97TYwT//w55n4Z6ka/SaU3bnouzxXkpEuPBz9VK5HJq13uYAhR3bbVig7EnbrtYusjynVUZ27LSmtd3tkAX3DjkHqgK+zxyWgjIbaIDK7LM6k+TBBSVCriowjkThQAc1BF9pfE+dzHc1DmXaOYYXpTIb3ydoJBaQsCbO9llBSAl0+mER0VBUGFZIx4D0TesQjQbc14DjBcDd90hNyMmXuDdK9m4wOFpzE5OdW6ivwcNXbRkUbD3Bv15z0yEUSUCAsoLczmJCbAJzQG2F2u0fKlxVaWz+vdnYpYDbFdjkTK0IW2OFwd63XIqhpQ8F6Wb5raGz/7zxG8AMwKbM032yoqPYDxtFZn0RYc9G6NCV4AoYGwO4GvxzUTePn+Qo6EViNlhcl4bWI3bKJpTZLHK+hf0PfkKyS8w1tfSxHam8A3gABp2YqfDFHIMury57GxdSNQSOFGct9sSZYLINzu0yUsWZuMjEw7fOLixFOZw8PDnMSx6UQ1632yjpJC1V8A53YuIiKFpIKn3im2a0AsET6RrsAInAVilazivhoyEtMUVMykI96QlQe167gPdw9EGRtwm/LwQsGQZGkMq8fAZw8sS/lVGZbusleyNWcJ3SlEHSorm1+DEAvQJqMyJ6xOCWd2mA7As23m4ATgNt75LmsRoOylW+qlobfMxdhq4GsCGYgDcssShQEalnAfbXcjr69zYv9v28BUWybV9YhDOzar4EU2TP+rn3RHnAtWQQ6Mx0gPVpy5Mg4xpDp4SjIeYo+6W2Akm2WC1fUf4QxVJUFWGVyFbSRMpDNOgEBN3b2f5OFWY1X44UaR2xFD538S+fNuiXC5kBk8acTM1Y7vGuxy3MImvi8Hr+UpCUOaj5gJfwT28Gx4Q/tGJ9T75uYI6KnaTDFItRqYpqGHkYkE3b9BX1PBrZlMO+8aqhSf8rRphfnyxYx3mlD/+3m/E6RgxrYhQrh90cYIxzYEqrphjWyrawB9FUQV9Dd/SwgLSLrm1q3TuGYz4PKcdx9l8APIGdZrYGF5cp+NbqvchKmaK3hHi1tEv9iujlZQiauSuRFroONGnEHGgK1GwGJk/+CRfTMWo073AgGi0IyMWTtaaNbaLKwgx6Ma6gAI2mDrHMUBLbDgz8QZV9nVLF//3x20LsARXf5V23sb/MJkvBu4d1VFYNIqDiwEGMF2ZyNRcEShXzBAEIPvo+wkg2Qb/s0kJvYh+SsJnnsHhHNGRBK31z/w+wR/nb5jgaxkTGeU4RKmwwNx5fgn2UeNXDHygHvPzSqzSiOjoysGfglnNwTmNc3hMV/zbc89dZwvqYax3FF2nLZtqlf3KplNn1poZR/6BOIeauJWbn9MzkkUizASUcQHmJ8/MnasgiJS2IvZoqNALhnp3ZT8pt+oLGT7injy87074QR++OXYbSt46InZgIzUmlgTr6eulXnOa99D8wZeZNjbpt5nyAM/3TMTDXy+ZkxRlS/GueytYfYPL80tAc7kjE5FpkvH3HPORQtWOz68M7caa1PxhQpHSxg0FrKrKT1hr4hEo7MP+NVQXQzqbrp5csAY0IhqP+R7c/wqf3eqzTq+H+z7gLTn9OpDY055yysi+xbEmaiJ1WFsjiUm7YtDqeALLVvEwuKGnfNobChnp1l6Sv/jjB0UHtWbo9ex04MvnqY7i9vroleXdMGPZTD8I1WIOqf/ZgYpNpO3i9eKdRmF4zJR1adXlAoq0QWXfttvsgmwcQ4ayow5E8ybCtlGK/RMJfLDA/RO8OFI3Hj14Fz9EP5VVroElnGfZ3IAQnjns05p/7DIZgVKcMGA4Hyrmq+joXIQtj1rk/YwLHcuqYEl+9hJH2Qoxg1PyVEek0JcMdmIJPe8BwZBPbY98Hyhexeg6ZLI1psR9SJsVfoPywbrkG0A28eHKhvFbYr7OfSnjFFGq2X1q6+sLDg3qv2bks2MOkzrW2S9sKDh1a1Yt/kFeFoFlPKnMy4SXisIYY7DyY8Y67NpEJkKcg0sml/XafLQLt02KBk1VzJSZWytV+Sb5GDcSnvpRKt/8elzl9kjjPx5mdOVfmL5AwluFNFIxYPn8liyYpEAOMIOsT7YXVUjgRAxBUWuhZNy+dCIO28XQQE2CUioce3AO3XyFP9tmD67Uk1p/2mujTMvwZ+sy4oyPXCHYIxOvyTnwl+3UGNn2JJqTNB58HgdAqdA95uJPJnclOC3G0saGF2Rxh2Aq7Ysvy5DEUuNq1ClM5CwHlZD+FNT3eGF94cRjYKBfAT5uZqToWMCmQYP5vgVaIPf6f5mTX60uoYK6g2/RM5Obw8MsaRybSbVYF7seK84XsCMb30Z98FV+pXizEJWpkJmoQR/Ajpf4nnIm2QkL0aWYQx1n/8Dc4YkzNNgTxAigBDlCfzdqvtaY7VnpJnJzNR5SaX8XI+NjzEMfcNufQqTQk1e3UZiOILVF7wY714Js6ZXKSr9x13g3qlP7k5GY0FESxpepr/rRmX6oxEAfP7R6SPEMSZ9cFIXktaKr7OKRAlKP2svR95O8UvzBVxARtDx/APOjyBRCXhCwcRfT4MfoUvluG5dPBohL7OYgud9i58E8kousJLxk7ZTdhadZamyxloeZOPNQzZ4NwMuhV0Ot7t0d8q4Dwtn5W64dPZotLFaeqUH8m8rFx3piwTCoFIhzP6bJVTDAqn/FI+cEwIXyb7PXkxAw+UzR2cwIMuaoPkVhEfCrwGUmZDDl5ATEKV6xVFGtiRILcf2QCa4LUFKUUZRjffNq8aTzRAA+KWzxhaTPaf8qbe3aduYmSg9WizSFiM5wZKMMFCImMNtKzVoNwltRcE/qN4GM8rWXL+maXzXahPecjvkAlqRzXQBYtWsKyLGEqEPqdrqHInLjJz8mPyRrYa7sd7EttF6ZEYiVoql8t8veFXim8R7zgOJEsiF1m+9N1tj9iW9CfAsXkY6EEceXYKGARhDB8+qIwNn7v1mDk+K5HOqtkvoFjhE7ieY9cuQ9wt3e22w4cnkgPIrsFmI485HGevwBLm3uBqO71nDFrfE0H1C5jH9q/7ZSRdbWEu6uNmybaJrPglGmki8erj5sNhaHIVgnO9/hhFmIYOojPCD/kCc3gqNGxn8Pn+9YE4Djh//KvEUy5Kbr0lJXIqoXBRnFb4qwV9fo8E9kZLRZnP6BhB7yjUjIu5jWCoKujlCjLeMvKCU2ZqnU9PMgCHCsWDPqKxhlbkvGSGOC/SiXxU9YrYv+rgFTHc8Qs45hu4w6SY4l+v3hS+K7D+40HPlsxYhYTMprBsBJcVRhmUNQtIAKIW7ZFhW7p1FQH9+hgaEnhonY/dycFxZu/qSPF3DTvS1IVHK5dMrKLE5jJk9yhqGVgzkNSl/R3vs0eX8xGhZdvwbAfdD2/Qr5KV59vARciSUhgz5VSv+OwPOt4VkuOixdEtycUifvqttZfDssyutNFGDOj1SFQ49szNIdPlhMDNfCGkTGWC/NG/83k/KQk2j7WShG0GzXWH1852KN9uVYT9Es2kskaWCZCEZoCcowSWZ05YYPhzMJGccLXTPhHgyfDEQchzzRf7wDa/Q4lrY99xfon62Ef/VY5Br70aByi/Hux3CfO7SnHRdG8Rj0G3A4ipxshBf5o7xq4d9HOlKmoLsUjgwUGxKaVJfvl0vvsEOLgGcqmFm8gIPJhQ0yUXsNJGT+Q/SVq4p98Y0swWBp3WlZcQZ1J43DPKhekdhbI+uH0/6LcRWMT35b+BnbMG3s3HGFsgTHNQpqfuTcisZm42j+W8ks9vab3jYey20q3MBtFqASMVu5+RgVkppEfxiMVJP6c4D2jmq0B4EGb293kFIjOt7t0bG74STW1FCNwc+z0KHbrocT0a70qlTW4kzOeno2pRCBiB+IR7nQfeFSvxHQ+TWRkEEWK5VHQLUnetFEIYxF9Mc3u9fcgFZZc7fKKEdl1/Uz08HTJHuIk+XHzkIAcpeFmAtCQ1qAvM0rZh3LIB3rFdtD5JVx/imX5zdK2ug1WUXvq5K/+rnTnIk7yC8Z5UvxJGF0/uoaO6QuCBYNG/rPY3a3Bq1Be7VKuf/C2bwgGGb6Zxvb6r7cFWBXD6tVlgWQnGwv9LBcZ8b+nubiNpFslIfmdj+PYdvbdhSILZGTeEDqEBTVeJ/R3vJD09z+5i9aRbisWlx7PDQ9rganAl96ciQuNeWkFl+D1WndhJtBPcQGRGika8ocLEqpphE1GVtxp9Dl+NbUWBYijFiXWAGB9exlWWIqt5rcFwLS910+OiPlP/Qopfvnd/noy4vapMev2C71jApir3Y7jGI0rQ8NE01rWmAVNhehyFHVk8LuVeJF/U8qAu1iohWg/PNyrC1xjUAEieZ/8JyXIbpKMPLpQ+T6ibSQZ10xoxOCyUeq33qZd/qNe3mPcHs4iNZmUGgfcBx73jieemSK42ct+iwlTdh7ra4x2/1Uy4bWi/YyQGKmHi5wWNIRu/cAKGqP4BUktbp2m7keQIpvKj6H1DnrM+e9qZhhsiYnktBZJH1L95Pn7HRFa261NqnQvK58jd22dOovct2+Fzx6jXbuKECJPgTe2ki+4DHZjw9q72e0ojP6G0wX0SMv/mBNiGZaJkHVozEzZFdf6E1c8bTIz2ahpVACfPZ2TpfXOfGCb6Te+l5mp6w4332YXfoHbwubUeqdS0+horUtfUk/1R6gcE8pWO/kcsIL6JBxvTQeicDrrMzKsndJlXIbQJFh0l33lhhiNd5EVWZjMexh3CRaHdTNyxf5FrIw/SAojSrdw2T9pv1Zwa9bNGga0W3IbmqV4bXm8Vgj49kiChSc5vXeTbqoRj4zHxmwXa6U1/DOlMmecS6AwE9CcWWwvY5DUboJwVGB3ohia3yz7/Wiqi4rGOcXtt8P4SEVyAxEilYnuOExmLO39T3/OwMM12h/4vXftjOaindHC+95J4lSDwpNsVTI2cKni+slL2GfWKpdegU7/RVDzKgSAwI9OEDu0yCywbhzQvhQGFzddkeSRPTb1wi4/6eO9sW7xHU51PDOgI/vTJ7hmdJrtiW+EjPDTxMvR7fjQZD6y0+eGBVRUxMl3K3Tll+XmROAXR2rrkbxc50DQttSwijj3RYO4e4/fNivsC59yGqCxgu9XPMm8vpd6V2K9KrA4nmQuD3iJOejSbjCCu7eZ10hYUZXG6IOrovlqpa9ff0vfHQVUyvxebI0ZvK79VYpTJEOaLvq3jx8CsOoTeDmH2W57eYUANzsN4y+WS0ZcZY1cbdy0rkqZNuNsfgHvlQLgt6Wtpc87zIRTYCos0jy1vuyzOFzK5LhGQAhOufvYTt6zAxwblbToPkd35PylG2D5lUm08KV7wulZD8YQg2mNMIBvxgwEj8jHLLA3YCzEnI3TMv56zsRfr0ibI5TZ1U94+dA9tX4WRmaptMEERiYBSOGuL8BIqyT8Iyg7Q/NqPTYICWMNoyvGAVwkhrikKKp02uwammworXbJDI8XIZnPo6QeVjwc2sCAB/TG4ILoJmPXkHNBY/tokddWrYU1S+TE4RMdrdsEYYBmxj67Ak53bLwPfTgNYJyu2jO2t6lcEpmMaoNcNNcLXb9V7MlVipcdhYihjgkWXl7a+Z9TXABL5MQIuvq4aCRGKPQYOryoGxjl3uAdi7i+DSh+1FcJBWrPeaKX5NFP+qSImGogJk4dOQARqI/TTz4ithpk4Etcmz7X9DlAhRugzLx1qBA5A3ObNLzvFc9wdMVMHpFlXVyfWGvpw9aYrDip+DZZKWparF+boVONnnLNHFGIO5D6R0Hk2Ax9ly0i+r7ZSwH+2rKTWFKSW2Dv9CMHRIQKxE1gAvS+4h2MmeWj9bXtX/U95F8FMs6x64HYYnREypxufHICLNolKPmwXAJ9sQVP0T8xdrGQDcscDoObjPnBBoX9WusWWxoMxYbLmB6031VVOpx2WOrpeOTkon9zV3CKpVsx6EVyFRhUHbksBvNno61F3vy65lZnec+7xkqugzZwm2T7RR/6iS1p9mdRnOUfaSOST84gCuSpCGbggwrOlOBFoWexm2LvECGso09IgMZE8QIM8P3PznEC+ZDvVWt5kNr0wxM0D82KalQ/HsA7rVdMnzG+N5NN8D2nhljbTMiZ4SsJWC+i4YXi5ZXqww1DVKJVnenClesJ6EqYC9PkOEfVSxWXcGLItnQ+1eRwmjEkc8uER3iEvqZ4rtKZXcWzBWXE3n7sGOKrc9nWYYuI4TcvJ4ER01rIK0Cn4r9WfZGmm3vTzHDoaAt5hylbdnzSx4pfKIQa3HYuKOaIq1b31H19FafvUvEp83+3gsekdE4kuvkKXCBhYOxKMr2ZRb5r6o4quh+6dayG2FiMKVe9T0GzlrwCFzEx4GWqPVkeNq48CljAfas80sFTg49wVxPQ3d//xQojmp1rs2XSC+2X2kOOnrANfvVzX1R+tvG0aAt0hsH4PikluazIedt9Klq8vSu2nPHx57glijY3RYvsf0VowA6/fUq1evCH+Og9AvbfLOShnzAzzBu8ZmOKuERCkFu9PMHyKML3jUK/pLXDMGsoMIq49e9mg1pSvZOmnIbsIuEpn/DQnZg/krtkxt9saSewDIvL0xdb2FZiJU13k+9OJNt9wTD+PA0OvzqfmyNEF60BgbZCnjfHAPY+SQ9rhJ5LfqAXIVDSgHy5JuobH4/F20SC9ERCTTpoMJoysmyqXbuKmETjJZeT9uE1lZD5JqqyvX1qAhZJxKju5wS3QuiO6Gy4jMM6aIbTVHApBN+j1DRXrMFaaxUFWaGK48rlQbmAFIOaTfBCZ3mP4OHc4LZwP9qOESawMzdg092TmXImHKTa7xQD+GOgorSH70k3uh4bpQ7J1zPKWKOUspEFiveHxJnXK6kvKkfG8YJyzFZPwIjqSzGEgGvbOOu7+bKBPl5D6kOAAl1Rs/Wz4MZhIkNUti/JchkBDP1IJVTOBrQe1nNu9u1tIBWmhPpT5qFpzJYrWq8TjaOsVeqEo9YYE/J7Xw1VZ/I8jZYn/EWavUa5T5Kv4DbdGeStPE9uLklDBIk7eCXiPmi7jp+WffHgB+hCgEopUCZhKlze/FfDwsFwAq1eQDFwu90q49+GEaMEVHjpmbfElA+7vBYIyvlBEKksZrFpyVf/L9SlZacDkfknX2ix1Nya0uXh8z3Qm9ipu0cuKuqxDZGIOYyFVEgMg/xGpytlY8IblenHSAHbj9VIO7aDdt4GXM8SgngdAiL+9CCXBv9Kq0eAsbebRCqy2Odr3uIgq/m8D3cJ4tL2T9reJ9O/MbBY0Y5NWcFxhhPBw3AR86xINxdj5lEQfwnRwMUZBhUJog8yW4i1X1uuyLGwgjeZ8VWqlw7nNYVF2xFISaGN/PTPqReTJ4I/bIdI8N/DWzbuSLYQ4I/bcWR9oCDst97QZglMvk55e/e1ifW6N045swy5etrvnow0W/HsULJNNbM6Z5Kq5z1WSOgJnEcr5cF0dpQdq6P/PdnHgFbVHzsVdGs0i2rw10eH8ZakE6ZOuTpRpfISmp1lvnUbhbW6olsfrsyS6nU5INrbtpMtdf1lnz1hZiYb8qCDKDkQr7DqjUufzkxchux82RgmX97AhLC801lZ0Jz07KesJyerFQ/95JZDNEkdKLea2I+CTfs9mPbZpHCuqTX4dwC5+XAFdoCcyxFpQ1S8LgW+Xpv/cjgoJxwENlbbtoFeLxHcsk5G2GDwKtpugd/69zaJxtDikHVGBbvfT6wpX4ZpAO/dw3i41L+vgvTu+99q2+f+PqS6NC6/qxRnto2QY1DTQokdJCrJj80eRcnXXJOxUgaQ6TgGNv/Oyk39K/sc/X4pMRURb0A5GQutEBfPpZjJJ2coOJClbsEL7+9ev7vCrxKf7buoVlBWc+rVGHEpVTiktxlas6ALIn1Weofx2lRZ1xViTVa6qm+97ks4HC0z2T3TAKtS1kQrNblx2bxiZ/d1rTeFNZLLzevRgGYfesorYOnxqLqSaixcaumd7OfozVBeDe69zc2wDCoqWSHXWz5qDBEclfgy2/KpzqkibQkORIVhitLnllnP7h1HpQ0YrFwIB0KD9eOIM8JSu/7Zbt4VKrl1PG3Y7eOulnKGlMBh0l1/zl4k/VWQG2ieLUK5FeixHcY8SBYGPGyworFqtewCR3dGk4OOl6wDDwEPUZnMafbfL1TH5L939C8F3xTVnmKYPFFViAQCU2DS8PWvFeQOvw2yghvN1fndgzAZ/FzkhqzmX8zY0ytDCEZf+OesGgCfkCLdelEiJ2GbicPqK8lDvoBSDXK/DDfHLZ+3vVBmDU99TI8dubR9HJgr6z4NLJrBFpM6S8+7liQsABlqDn/HsP2SM7dXCoNbdvXWhyj0ypfoCOUShSIR95LMUL5SjQvSU6vIsfyun2AVekessDw1AOAP5AN0IEK7lDOW2HLD0uH3Qxasdcvwrxf+3SjTRAwAoNoNRcO8Tup8eIbfLpEn+md1nWObWQuBSmQDfx4kblgjFmErQ2SiLE291sDGoukvvWpnAXxT9iFgZM7kAcqXnkQpKTYutGpjWNyoW1Ue731E6+TfmDp9FQytM92fvCkFt57OJffgucWtTPdQdV5yipXUalZ16G9iP9hudzCnj3DSWaVrip6pR4hWmBeHIuZ9Vp11mixsP2JDO6cXj4XFg3qocBHPHriCSAsNCKdx+9a7LHQaI3GvPOIhhha615FQf/1Dr0/SeWPdYOTdr6XCezUdzAttGmcHSPGkqkFmvlUvub5edZOUxLxF/cJra9a03Ui2ZF4Zja407glsKVg/HJEXQZF0SVTy3mX8l//FtLE639PBl/+mv3vnzsfmrgIRmKCvx/bQ7EVTDjf71zGoWz24P6F1l1IgVTMBf9IypoNd80I6h4HGqfw2qPlMlLYG2oqpwEKQhUrYULt7YVi40WowqRoWauN6oRG47DJkMvveY7yqpRGFr1JYcDhEeFh8KALNI9Dly6qPolxLatUPCJ7AiOem7RjgYKYSSaOvjB9cRRQ5uoiNC1G7I0Fy+juMF10D31rMtxw/Z5pb5bt0iu3UlsbWPf4c2jNEJPf5ukVhfWxEA+uLe6nL5w+74ncujrjCGJr8S1NgfiY8IszJhX40c8TDrLoi/bmcu85JBZq8CH8iXEXlC81zQFhZt4mcCoHXTBT1oog4EUC76JcQFNcoY0TNuUsqULqo0p9Nsqea2WVHtVPA2YBjIoj6gwc3Fm0FVaqN+BnCU7WBivW3Y6I4Dls+uwBpsMYlHjy2IuK4yOjmwnKTFmlXD0D4/iaHKTFen5HdP/60BKGeAFkQSv1xzTR2qTZZkHvuQR5FqCJYpqSG28E2NZkHrEUyI+6zea1oZjPcRGHqWdWqezl61zhivub9L6rU7ZtPZkY3kegJ3X6bMxJdLn1NPwfHLC8eeL/tMeOhQIGAX9Fn1bVZhbVdXgq4Iu75LbkSEvaysrCuyWbkhxVMOzzMWDOCLJZ/tbtPSKTkq3Ls38QlJDi7Mz8gMIqg+KEPnYASmUED8pUzXXviN+bHfNCsugoz9P1o/MryCsY3gatuvlyG344UlGLw46ZUhmlPDfD7fVWr4LQ/Tx3uWPt3vnrUOznQFmR3uOnAd0zV1njRW5Uv04QQKQRpuFKROqC6XTwogJMlFUEOlcAULcc4MM07a7J4Z6TubEXtue0+wS0OLYybhMg6accspE55bRMHKY9w9dWjGqI4KdkPif13+yzhy81ZSXFtvLCugTSi0IPS00woF+f4x6ehGlqVD+Kt/+XAloNdc2T62JTM6y1AGIBu6w1LjEhfcS42nJT4AOcDpVwKDJK41jmG4Oy9gdapiKKw1lpcS+YGniVcKnUMpm3iNzx48zWoEWAZMwAKt4t7CjHSWE26SvAMEbrBFh6GTB9zOj87zBMVYhrbwSEcFgEQ8KfiznVZOtOurWMui2GLvn2bevJ12Vx0JMNcCOQyJiBydujlwpqOBOCcXM87K1xubHpO2QCJDCiXB4I5WR378t46kb9E53zP6A/ONN+AxPirnvlJHQ3Fqh9+hIgKrZ3qRvLG+9YyWBDawko7HMQ8CQPJ6Jz9k6kpIlWGihxlyKY4bjjzB4Yin6uWupdKJXUjVk8wXittCnQNisE39VhJvuEZY7lnHqSlpKYUI7I/ADyXyhHVOkpnbzZWOeT1Yr5IRGeazyjW+B2qSrsMqyUrDYj4rbgzpXr2E0W5sBKMWYGJoOB3ooLtkri5AteO0XVlc1ri69jnKCBUcm1VPrGr4HoNS91zZ+tugMg2DlQpW0XLDWgTRtpTRru6qe19K1dmC7cVV9oQqhtA0/VHUTs9Ye22dbQyH/En3K/cBXyXheFjUhndC7eomqQPOcIrKnLC/apMWPf3QOfaNkhxo7PAOkqdfoVIrCn6TMiku2rd/gZoaNc2BfcGGK77tXF6qB7l9pzIu0xIE44sjaOyKRyJPhX3sEbz6oXZ6OkbDumI75GIkkxEplM0f3B3hgMapn5KO2kCRXDXMfIcqJWUzvGCAe+76kUalqgaMzVkRZb2RqJJopOhxCg5YhLve0/nM28HVSO/WEM39FCrN/kXJiQPbsBqUTIrs3QZwuDwvirf8XV1F92t3+PROXooejtSyVIgn7jztYhSlgzDWeEHC/6SWrLuXrjUemhhlBqTCY9HCNg7H6r0wWu0fo84Tc5Ty2xDrhfGESKxEnVzuFwhRNyobh7tR5Z+9QpdB2M7TQnAGItJrVHNHRBntwx4FfAh6jil+hVH72oMbrLQUTIBG1xqk9QewgEG2yKtYRcqbbT342r3gvS2IyqkYaFBJ89op1+WG07hdCYbBTGJt1C9EN7J/w1mVRO2bFkH1pRlBv91KpctOTHsn0yJBb1XyfsfwgCLcstDbjIsX84M6xPRRsyZFvtBNPxBzrwLFWH6XwE1IXTqeiKfMuhVz6SdzfH4DjKoRkDAH8wZwVdhRDWl7/+rxbDNusm8OMt4GtFln6yy0WEdENO62E1OdGbBjxABxN8OFJWyG0DEtBvzNT8o5uyOw02Nd/9RnpuztbBoXcTKAjSVpNXLXvAVw2SP0gxjIkGoAaMoJbJYZ+5b99xZHkHRDl++qLs4hI80qZ8pNQiCYNWrHPEf/8/PnYJMILr24j5uOxGikF522pLQDvJ7btHyYbBgA/wh87mcnVnCmIAzlVPMHX8BIvIWeT0sResDJnpmRHoRy4U5uljDgYwctYAZrLmCVlTNlwATBOpgh6t6PYHRe6+3lwRANsMgoGG8QzqXIIKshc/icyN+6avbw/UyEFBVdXm+/e40SLxYuImnzQ35A/lBriXmgQPn/RtlSe8XS6mTLZwz/f6NYVqW/jR9e6GuPGZjIA9XM7uefW7+GHjRz0ctDXY5tb6aNMNcAn63rg6Ku2gh48rmvXtnmn/cesr5W8+6qwG9gl+hNaDHMfttnnpwelZpJVlG4Cabae5zAmGD+2eQVc0J9V2bJF5yeLhn9VaOxJacHgKDPVdP7jv3CH6XAwhgog7uuYk0jKPX1yDIkmb2LOgLuHtTuEUgki99kMaKGXANQtihT4l/9vQU89FwQdiqjY1vtzc60u73tKklteQ9rZ1VaJezw+zwiTcdE1ipl8DeNxxwYCQbPqkauutWCYsDJdmKHH7g0sJIsA5+6x2Isq83Bn7kTzdtXRM4obUWz8ZjXSrodG+bSXMiJ1X4fkNb/AhRhWpZRbkPdaIDS9kCJi1qgheEp5lX3+f+FScF0D/pyvfblOss9Fc1+Z7FofhUwrYpsXWsnXph43ahgww3QXjfveEZHQeCbAzU/SNpdLH8kYcT6dQJ9w5Ws0QalAcgiRtMcV91H9Uwy8FwKZvCEg3I1/PSHy7sMrscXSLatyy5qWob8eyaTT+lCco8i2WYmbsx6YExV9X0ZJSwPW6zEjnKCSC0NZvzkI2dWKU+WbRrhP2FSpCSxgFXOn32jiFLJDvI9F+YXxRxwIVa9Jxxp0b9yoRCEIbN0f7OKmAYwGkbot2ZQB6H6Ej1i4FqLdl5v88Xpw5wio0KGLItOatE5OOdoQbwhbTD7TgBq88Fi6GvMfvIb7yKCFS//9L8BgE9RGEGMfPOMTlajSaXtQu108+bXvxPlav2QgxMz6pghAaoDo05BctoUSAoFfiDWWW4HohfZqhs3mlr986J/sm05+G3cpUh3Siw9kiZZc+zLO+CWrsX/wigvQE/BQXBMbHwOd8el1oOwEgoOm9eg0xonZNEOeQXs2rGUj2XeZrmZjHMHXBVsa6Ic4r5jB1FXNFOVC1ZnRSTr0lsaiXL+/+9rtigucsEmwku74OiyWIq6jEe9DZEk4vmlceM8AbeWqEiddJXpBX1BTSto7NHxqSUzxL1AZR7S57+O9hcaJMEdBBr2te43VwBXnzGnsGzddck0l58GNSpvtjDTVPB4i09iew3WeW39a2zO2Xx2keOLSWo26l9oZLEBmBFk7odlphvkqZBp1G4wB3SXaYwS6KtCtldPNilHowmSI796CR6TlJnL6Ay2NcM3ydC3cmD0ndDy7530mQGDwF3+5o7Lm7ngKsyWJRAQ3ouQoPhVeC6ueXgLnnf3yeL+OatONO2AjowPjEVRApvPyryXH1df2j9WUn2y9woUOzSHHX2CUJxmvuvzfIFG4X/3Vmp3jpbC0xNe4m/M3HFKKtI2UXVXSypSYMVRf1mY7fbCaMYeNdiTrtU8v5DIY9+vvpLA0FpZUy016D9488nRgKwyP1svRLw1uxQ/8MHHwY1zWDhquDmJ8Js0OBdFik5ZAePoaZys4g4ZaDqM8KZ9ISiaX8wERjP6rJ+crW1Ra5RIyRthUwXDxM0jmD6LUWptmuot7ctfOK1Ex597lsdy2lSVQKm3Y0qhIHjd+3GaHEj3l/tkJDo87g1wfPwIFHWITJMTsuqNATe96y6YiwsKU6d+Jj+lC1hk4XR6KGOHaDg8U4CNQzV6MF7HVwYOhNzF2UnboR0TuTX1SZJTiOCZwkPfPbC5+t4q00hHJfb+MHhYJ6oYk/zL5widOWK3ZdZYOMssY06TZagDX8SsGT6eSmkL6wgUCDYm2KZ+zA64Ge8NHuWUPzL2vLAAzTvVbZ1ehP9nABkRIEDKEj3gKYW4SYKYfuO4jvtbjUp5OuNy05Id2clSB3ZlGOxs33VAOzzVWDkGYzmniAKpACPb3LsrcS7PyQJ67lYDBztKamsNSJ0BFTwLH47OJ//fxTd10LOU9tATdFc9M6UGUSEzTwWbP8EOPSpttxBU5bQvv4nGLTgw7dOCFm3giEj3RZo6w/KcfR49LohHLXoofqXYQl63PmRrjRWxm5YJRB5IUEqTl2+8o3lvotNLHEauc9vKk9Js/EUzw+Tk4dL2O0JVffv08+ASl5/CLpcQnuS+5Mm1hW+9H67t0677FV8WxKFqoY4kw7Jsa8sB1DKwae1JJf7fCufkJAZ/EKLccQrd7bHG5SZfIEGZTvjzGFKob975iK2GWOrxwWHrY4a7nD2332Y8BpwiuTbdCTTT6XGBR3tzJHBH2R9ms3ALl0zKFTj5qreQzhGkTAmw6Je6Y4EWfaTgEtHsnfT5W27ycOYe6C2OQstjsbF1B0EssfHEYlfzKmaOfSdTvA558PeHkc8sVybbAsJOKGz7zfY9TgMHPtfUWDJrOEaFms3mtdhG4l3HjYNrbHRVoPBprwq9QTicUuGU856e9ZYBl41DhjJZ0/vNxzXlG0pyDXVLFfZVCcCg8SfeMbypbtSRF2uirCRbtsdxCzx9DDyatmtf0g9N/bhOQnUqKkgECwkrndGc6MHEkcBz0TSIkDY0lA9ema+6Cm8eaUstu+jOBRxdP/AQubC+tJE57ZNAIvdfNDeIEvQeHKfiXPB4YIyHJVcV4=</Value></TokenEntry></Values></UseKey><Claims><Values xmlns:q1=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\" soapenc:arrayType=\"q1:TokenEntry[16]\"><TokenEntry><Name>SessionKey</Name><Value>srFt0WXjAf0dFs9eEE7Qib4MgCtmWAMIw56XWo8KFQJbvh36RarK9+raZo/6qfA6KQFDzVOVc6J+yAgBUFztlDSumXvUa1lkEf/y8KIqhanTy4tbf81hD5Gi3P3YOe30+46zRH68YESOaUXNisae52BaF2ccbIpDwMuJB9QoBfxAXiSc9jwR/slyG77fIqlbHmgWRQRUnO8511k0D09f262ZkZOX7Ihp/toRbxl+09Q/em4Mds4B4GTuOgHavXH/HeO63gZmgsI2E3Nk2EzwXtxQhmM5GrtAtSur8fC7CteI0lShlG6el99QKpIOTiKY0B74IHNczRc4Rqfj+0Xwrw==</Value></TokenEntry><TokenEntry><Name>BindingType</Name><Value>XQcXT0Z087s0OHTucsorU31wwIgaiGlaE9Gvfsl1Qs8=</Value></TokenEntry><TokenEntry><Name>Binding</Name><Value>lOCa2nTb3hfU2n2L2mySlnm3vbnKnV0yfAtO8diIb/LIYCsI6MAwHit8LZhBBz6cg4R6L8RpCldwwS3tqcPz/tmSLEbwPDVSHrXejzQPSfdhxH+O9sa+IJiX7cu00WMr</Value></TokenEntry><TokenEntry><Name>ProductKey</Name><Value>PDNuZZ9gykDaI/Y5daTxVwS7AsyoAEByPG1L8ZTQCQY=</Value></TokenEntry><TokenEntry><Name>ProductKeyType</Name><Value>XQcXT0Z087s0OHTucsorU+ijTN5tnbQm6fC+8WhcPxk=</Value></TokenEntry><TokenEntry><Name>ProductKeyActConfigId</Name><Value>+ep4+O3aH99nCjEUiRrIdqQtg+AgcyGHmW+94SLnrdOKWp6hP6t1WKA1OPcmBfvxnO5a2HZzil2veczPa5m0LG9fXznnE1saCLhApzAAL7w=</Value></TokenEntry><TokenEntry><Name>SppSvcVersion</Name><Value>NLbhZ+DntyInPBkbYtYWTw==</Value></TokenEntry><TokenEntry><Name>otherInfoPublic.licenseCategory</Name><Value>ye5rJI3ej0rYrshq3wHWES2kUCiKNkhXDvpFVB3BbrU=</Value></TokenEntry><TokenEntry><Name>otherInfoPrivate.licenseCategory</Name><Value>ye5rJI3ej0rYrshq3wHWERQT5y2miQ+SE6RZUg8jsqs=</Value></TokenEntry><TokenEntry><Name>otherInfoPublic.sysprepAction</Name><Value>sBtMi/NdmMNpnTcxlwtQ3w==</Value></TokenEntry><TokenEntry><Name>otherInfoPrivate.sysprepAction</Name><Value>sBtMi/NdmMNpnTcxlwtQ3w==</Value></TokenEntry><TokenEntry><Name>ClientInformation</Name><Value>p13C0W+OxxKLaAZZZcvKZxunjo2kaS4jpM+bu7K3Z2ofYvAPuHt+y5h/QxbHqqP7pq79PfACN8/l+mgZ9/jCZA==</Value></TokenEntry><TokenEntry><Name>ClientSystemTime</Name><Value>yU+Ai4XE8M2HIo7aKgb9yT476rkftPamKEryXnm5LMk=</Value></TokenEntry><TokenEntry><Name>ClientSystemTimeUtc</Name><Value>yU+Ai4XE8M2HIo7aKgb9yT476rkftPamKEryXnm5LMk=</Value></TokenEntry><TokenEntry><Name>otherInfoPublic.secureStoreId</Name><Value>mbNQfWacyQKipHNKMKFu4ZX5vpGWWym/a+r5btm+mYFsOilKNcX8zHcPn/4P5zw8</Value></TokenEntry><TokenEntry><Name>otherInfoPrivate.secureStoreId</Name><Value>mbNQfWacyQKipHNKMKFu4ZX5vpGWWym/a+r5btm+mYFsOilKNcX8zHcPn/4P5zw8</Value></TokenEntry></Values></Claims></RequestSecurityToken></soap:Body></soap:Envelope>";
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://activation.sls.microsoft.com/SLActivateProduct/SLActivateProduct.asmx?configextension=o14");
            byte[] bytes;
            bytes = System.Text.Encoding.ASCII.GetBytes(requestXml);
            request.Accept = "text/*";
            request.KeepAlive = true;
            request.ContentType = "text/xml; charset=utf-8";
            request.UserAgent= "SLSSoapClient";
            request.Headers.Add("SOAPAction", "http://microsoft.com/SL/ProductActivationService/IssueToken");
            request.ContentLength = bytes.Length;
            request.Method = "POST";
            Stream requestStream = request.GetRequestStream();
            requestStream.Write(bytes, 0, bytes.Length);
            requestStream.Close();
            HttpWebResponse response=null;
            var result = "";
            try
            {
                response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    Stream responseStream = response.GetResponseStream();
                    result = new StreamReader(responseStream).ReadToEnd();
                }
            }
            catch (WebException ex)
            {                
                string exMessage = ex.Message;
                if (ex.Response != null)
                {
                    var responseReader = new StreamReader(ex.Response.GetResponseStream());
                    result = responseReader.ReadToEnd();
                }
            }
            using (XmlReader soapReader = XmlReader.Create(new StringReader(result)))
            {
                soapReader.ReadToFollowing("HRESULT");
                string responseXML = soapReader.ReadElementContentAsString();
                return responseXML;
            }
        }

        public static string GetSLCertify()
        {

            string requestXml = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\"><soap:Body><RequestSecurityToken xmlns=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\"><TokenType>RAC</TokenType><RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</RequestType><UseKey><Values xmlns:q1=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\" soapenc:arrayType=\"q1:TokenEntry[1]\"><TokenEntry><Name>SPCPublicCertificate</Name><Value>&lt;r:license licenseId=\"{c291d3e7-efe1-4dad-856f-b7bb5e60467d}\" xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\"&gt;&lt;r:title&gt;XrML 2.1 License - {msft:sl/SPC/ACTIVATED/PUBLIC}&lt;/r:title&gt;&lt;r:grant&gt;&lt;r:keyHolder licensePartId=\"SPCKey\"&gt;&lt;r:info&gt;&lt;KeyValue xmlns=\"http://www.w3.org/2000/09/xmldsig#\"&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;455AF+q1hdtOI7Tce9KmyGZKUiQ2Tg8GWFo4JYUqz9Q2fZWxOY63zzOoxkgX5ITF3pTTEydAV/vBGPsIAqDTutsBz+d5qhPbYPGzFTAFsxL+KhGkn7NTGZQoRlfwQgebiGEfALKy4h1uWIbHhqyMjgF6KNGVhNGzA3yE2hsfDCs=&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;r:possessProperty /&gt;&lt;securityProcessor licensePartId=\"SPData\" xmlns=\"http://www.microsoft.com/DRM/XrML2/TM/v2\"&gt;&lt;tm:assurance xmlns:tm=\"http://www.microsoft.com/DRM/XrML2/TM/v2\"&gt;urn:msft:sl/Assurance/SLS-Default/1.0&lt;/tm:assurance&gt;&lt;/securityProcessor&gt;&lt;/r:grant&gt;&lt;r:issuer&gt;&lt;Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"&gt;&lt;SignedInfo&gt;&lt;CanonicalizationMethod Algorithm=\"http://www.microsoft.com/xrml/lwc14n\" /&gt;&lt;SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" /&gt;&lt;Reference&gt;&lt;Transforms&gt;&lt;Transform Algorithm=\"urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform\" /&gt;&lt;Transform Algorithm=\"http://www.microsoft.com/xrml/lwc14n\" /&gt;&lt;/Transforms&gt;&lt;DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /&gt;&lt;DigestValue&gt;qievKyf5UwTCAvMlGhjFPltwZ3U=&lt;/DigestValue&gt;&lt;/Reference&gt;&lt;/SignedInfo&gt;&lt;SignatureValue&gt;fI9dh/AdVAlzMDoOJ6NYsNyCHOQrBuQDGX+vC10tTspZi47HQfYHQUzGP062On07PpFFyIoUjLMwoyVMBareoYnqqCqDKBiuqhqGVru2r5zHsjRT8PrPBm+G9WCyHop5TAfrJE2OTFLCL7yxkyjMnnVDqKoXlWS9a4IJViJrwcBURYLXpKeJtZ/Sekds+4dSlDthdeiiGLC01+1ou8PBAUebBQahlavnn9p1Iibg5OLgi2x5ZrcgTg4j8DNYKBZXG6GKbK5J3wdlx9Q5uTglYv6Zk7rTSaAG8qTsevOFBoDJBT07Dkbq9zRidj45t2z7C5mPBGR7Byhj77KLjoQ5+Q==&lt;/SignatureValue&gt;&lt;KeyInfo&gt;&lt;KeyValue&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;5peib3RqV+TBpGM5w4CSa1AhjLCMvjvxnQXlG7N5N7SyE3LDVtPr0zOjm0XSEZVU14Lw7c/Y/kVWhpUD6ONv4sDeR95w7eHskZGIOn36jSuV7I8tuDDaRbXDi8Ou0LH8XCqcjESjSD5JICStYuBg4tUdSYlH1pCXdcPGtFdLiKNUWr91svU7fWswEI75qUHMMvXDTousBPnqzkAMae0BVTkhJE1g2ICMNlyKoCdAzXGcx6M9a4oITjqWXgw078um4SEr1OWhzltJU97FG17q8W46ROHaufsmsb0LDLiqJj1VOP411l8MyQkeQQyUTQG6YfvSNe9XZTbW05xOEzLLPw==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/KeyInfo&gt;&lt;/Signature&gt;&lt;r:details&gt;&lt;r:timeOfIssue&gt;2019-01-09T07:22:19Z&lt;/r:timeOfIssue&gt;&lt;/r:details&gt;&lt;/r:issuer&gt;&lt;r:otherInfo&gt;&lt;tm:infoTables xmlns:tm=\"http://www.microsoft.com/DRM/XrML2/TM/v2\"&gt;&lt;tm:infoList tag=\"#global\"&gt;&lt;tm:infoStr name=\"licenseType\"&gt;msft:sl/SPC/ACTIVATED/PUBLIC&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"licenseVersion\"&gt;2.0&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"licensorUrl\"&gt;http://licensing.microsoft.com&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"licenseCategory\"&gt;msft:sl/SPC/ACTIVATED/PUBLIC&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"issuanceCertificateId\"&gt;{57d6dc1b-f556-4f5b-935b-3b379fd9dda8}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"sysprepAction\"&gt;rearm&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"spcActivationGroup\"&gt;msft:Windows/6.0/SPC/Retail&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"privateCertificateId\"&gt;{1fc6170a-8466-4538-89ed-f2c406c3592f}&lt;/tm:infoStr&gt;&lt;/tm:infoList&gt;&lt;/tm:infoTables&gt;&lt;/r:otherInfo&gt;&lt;/r:license&gt;</Value></TokenEntry></Values></UseKey><Claims><Values xmlns:q1=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\" soapenc:arrayType=\"q1:TokenEntry[8]\"><TokenEntry><Name>BindingType</Name><Value>msft:rm/algorithm/hwid/4.0</Value></TokenEntry><TokenEntry><Name>Binding</Name><Value>NAAAAAEABAABAAEAAQABAAAAAgABAAEA6GFc1g8W2YLf4Oa3DFxiBfwU5yFjqdfx3dxwKA==</Value></TokenEntry><TokenEntry><Name>otherInfoPublic.licenseCategory</Name><Value>msft:sl/RAC/ACTIVATED/PUBLIC</Value></TokenEntry><TokenEntry><Name>otherInfoPrivate.licenseCategory</Name><Value>msft:sl/RAC/ACTIVATED/PRIVATE</Value></TokenEntry><TokenEntry><Name>otherInfoPublic.sysprepAction</Name><Value>rearm</Value></TokenEntry><TokenEntry><Name>otherInfoPrivate.sysprepAction</Name><Value>rearm</Value></TokenEntry><TokenEntry><Name>otherInfoPublic.racActivationGroup</Name><Value>msft:Windows/6.0/RAC/Retail</Value></TokenEntry><TokenEntry><Name>otherInfoPrivate.racActivationGroup</Name><Value>msft:Windows/6.0/RAC/Retail</Value></TokenEntry></Values></Claims></RequestSecurityToken></soap:Body></soap:Envelope>";
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://activation.sls.microsoft.com/slrac/SLCertify.asmx");
            byte[] bytes;
            bytes = System.Text.Encoding.ASCII.GetBytes(requestXml);
            request.Accept = "text/*";
            request.KeepAlive = true;
            request.ContentType = "text/xml; charset=utf-8";
            request.UserAgent = "SLSSoapClient";
            request.Headers.Add("SOAPAction", "http://microsoft.com/SL/CertificationService/IssueToken");
            request.ContentLength = bytes.Length;
            request.Method = "POST";
            Stream requestStream = request.GetRequestStream();
            requestStream.Write(bytes, 0, bytes.Length);
            requestStream.Close();
            HttpWebResponse response = null;
            var result = "";
            try
            {
                response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    Stream responseStream = response.GetResponseStream();
                    result = new StreamReader(responseStream).ReadToEnd();
                }
            }
            catch (WebException ex)
            {
                string exMessage = ex.Message;
                if (ex.Response != null)
                {
                    var responseReader = new StreamReader(ex.Response.GetResponseStream());
                    result = responseReader.ReadToEnd();
                }
            }
            using (XmlReader soapReader = XmlReader.Create(new StringReader(result)))
            {
                soapReader.ReadToFollowing("Value");
                string responseXML = soapReader.ReadElementContentAsString();
                return responseXML;
            }
        }
        public static string GetSLCertifyProduct(string ProductKey,string ActivationID)
        {

            string requestXml = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\"><soap:Body><RequestSecurityToken xmlns=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\"><TokenType>PKC</TokenType><RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</RequestType><UseKey><Values xsi:nil=\"1\"/></UseKey><Claims><Values xmlns:q1=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\" soapenc:arrayType=\"q1:TokenEntry[3]\"><TokenEntry><Name>ProductKey</Name><Value>"+ ProductKey + "</Value></TokenEntry><TokenEntry><Name>ProductKeyType</Name><Value>msft:rm/algorithm/pkey/2005</Value></TokenEntry><TokenEntry><Name>ProductKeyActConfigId</Name><Value>msft2005:"+ ActivationID+ "&amp;oEROiKcBAAAAAAAA</Value></TokenEntry></Values></Claims></RequestSecurityToken></soap:Body></soap:Envelope>";
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://activation.sls.microsoft.com/slpkc/SLCertifyProduct.asmx");
            byte[] bytes;
            bytes = System.Text.Encoding.ASCII.GetBytes(requestXml);
            request.Accept = "text/*";
            request.KeepAlive = true;
            request.ContentType = "text/xml; charset=utf-8";
            request.UserAgent = "SLSSoapClient";
            request.Headers.Add("SOAPAction", "http://microsoft.com/SL/ProductCertificationService/IssueToken");
            request.ContentLength = bytes.Length;
            request.Method = "POST";
            Stream requestStream = request.GetRequestStream();
            requestStream.Write(bytes, 0, bytes.Length);
            requestStream.Close();
            HttpWebResponse response = null;
            var result = "";
            try
            {
                response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    Stream responseStream = response.GetResponseStream();
                    result = new StreamReader(responseStream).ReadToEnd();
                }
            }
            catch (WebException ex)
            {
                string exMessage = ex.Message;
                if (ex.Response != null)
                {
                    var responseReader = new StreamReader(ex.Response.GetResponseStream());
                    result = responseReader.ReadToEnd();
                }
            }
            var retstring = HttpUtility.HtmlDecode(HttpUtility.UrlDecode(result));
                try
                {
                    XmlReader soapReader = XmlReader.Create(new StringReader(result));
                    soapReader.ReadToFollowing("Value");
                    string responseXML = soapReader.ReadElementContentAsString();
                    return responseXML;
                }
                catch
                {
                    XmlReader soapReader = XmlReader.Create(new StringReader(result));
                    soapReader.ReadToFollowing("HRESULT");
                    string responseXML = soapReader.ReadElementContentAsString();
                    return responseXML;
                }

        }
        public static string GetErrorCoderWin7(string ProductKeyCertificate, string RightsAccountCertificate)
        {

            string requestXml = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\"><soap:Body><RequestSecurityToken xmlns=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\"><TokenType>UseLicense</TokenType><RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</RequestType><UseKey><Values xmlns:q1=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\" soapenc:arrayType=\"q1:TokenEntry[4]\"><TokenEntry><Name>SecurityProcessorCertificate</Name><Value>&lt;r:license licenseId=\"{c291d3e7-efe1-4dad-856f-b7bb5e60467d}\" xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\"&gt;&lt;r:title&gt;XrML 2.1 License - {msft:sl/SPC/ACTIVATED/PUBLIC}&lt;/r:title&gt;&lt;r:grant&gt;&lt;r:keyHolder licensePartId=\"SPCKey\"&gt;&lt;r:info&gt;&lt;KeyValue xmlns=\"http://www.w3.org/2000/09/xmldsig#\"&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;455AF+q1hdtOI7Tce9KmyGZKUiQ2Tg8GWFo4JYUqz9Q2fZWxOY63zzOoxkgX5ITF3pTTEydAV/vBGPsIAqDTutsBz+d5qhPbYPGzFTAFsxL+KhGkn7NTGZQoRlfwQgebiGEfALKy4h1uWIbHhqyMjgF6KNGVhNGzA3yE2hsfDCs=&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;r:possessProperty /&gt;&lt;securityProcessor licensePartId=\"SPData\" xmlns=\"http://www.microsoft.com/DRM/XrML2/TM/v2\"&gt;&lt;tm:assurance xmlns:tm=\"http://www.microsoft.com/DRM/XrML2/TM/v2\"&gt;urn:msft:sl/Assurance/SLS-Default/1.0&lt;/tm:assurance&gt;&lt;/securityProcessor&gt;&lt;/r:grant&gt;&lt;r:issuer&gt;&lt;Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"&gt;&lt;SignedInfo&gt;&lt;CanonicalizationMethod Algorithm=\"http://www.microsoft.com/xrml/lwc14n\" /&gt;&lt;SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" /&gt;&lt;Reference&gt;&lt;Transforms&gt;&lt;Transform Algorithm=\"urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform\" /&gt;&lt;Transform Algorithm=\"http://www.microsoft.com/xrml/lwc14n\" /&gt;&lt;/Transforms&gt;&lt;DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /&gt;&lt;DigestValue&gt;qievKyf5UwTCAvMlGhjFPltwZ3U=&lt;/DigestValue&gt;&lt;/Reference&gt;&lt;/SignedInfo&gt;&lt;SignatureValue&gt;fI9dh/AdVAlzMDoOJ6NYsNyCHOQrBuQDGX+vC10tTspZi47HQfYHQUzGP062On07PpFFyIoUjLMwoyVMBareoYnqqCqDKBiuqhqGVru2r5zHsjRT8PrPBm+G9WCyHop5TAfrJE2OTFLCL7yxkyjMnnVDqKoXlWS9a4IJViJrwcBURYLXpKeJtZ/Sekds+4dSlDthdeiiGLC01+1ou8PBAUebBQahlavnn9p1Iibg5OLgi2x5ZrcgTg4j8DNYKBZXG6GKbK5J3wdlx9Q5uTglYv6Zk7rTSaAG8qTsevOFBoDJBT07Dkbq9zRidj45t2z7C5mPBGR7Byhj77KLjoQ5+Q==&lt;/SignatureValue&gt;&lt;KeyInfo&gt;&lt;KeyValue&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;5peib3RqV+TBpGM5w4CSa1AhjLCMvjvxnQXlG7N5N7SyE3LDVtPr0zOjm0XSEZVU14Lw7c/Y/kVWhpUD6ONv4sDeR95w7eHskZGIOn36jSuV7I8tuDDaRbXDi8Ou0LH8XCqcjESjSD5JICStYuBg4tUdSYlH1pCXdcPGtFdLiKNUWr91svU7fWswEI75qUHMMvXDTousBPnqzkAMae0BVTkhJE1g2ICMNlyKoCdAzXGcx6M9a4oITjqWXgw078um4SEr1OWhzltJU97FG17q8W46ROHaufsmsb0LDLiqJj1VOP411l8MyQkeQQyUTQG6YfvSNe9XZTbW05xOEzLLPw==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/KeyInfo&gt;&lt;/Signature&gt;&lt;r:details&gt;&lt;r:timeOfIssue&gt;2019-01-09T07:22:19Z&lt;/r:timeOfIssue&gt;&lt;/r:details&gt;&lt;/r:issuer&gt;&lt;r:otherInfo&gt;&lt;tm:infoTables xmlns:tm=\"http://www.microsoft.com/DRM/XrML2/TM/v2\"&gt;&lt;tm:infoList tag=\"#global\"&gt;&lt;tm:infoStr name=\"licenseType\"&gt;msft:sl/SPC/ACTIVATED/PUBLIC&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"licenseVersion\"&gt;2.0&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"licensorUrl\"&gt;http://licensing.microsoft.com&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"licenseCategory\"&gt;msft:sl/SPC/ACTIVATED/PUBLIC&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"issuanceCertificateId\"&gt;{57d6dc1b-f556-4f5b-935b-3b379fd9dda8}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"sysprepAction\"&gt;rearm&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"spcActivationGroup\"&gt;msft:Windows/6.0/SPC/Retail&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"privateCertificateId\"&gt;{1fc6170a-8466-4538-89ed-f2c406c3592f}&lt;/tm:infoStr&gt;&lt;/tm:infoList&gt;&lt;/tm:infoTables&gt;&lt;/r:otherInfo&gt;&lt;/r:license&gt;</Value></TokenEntry><TokenEntry><Name>RightsAccountCertificate</Name><Value>" + RightsAccountCertificate + "</Value></TokenEntry><TokenEntry><Name>ProductKeyCertificate</Name><Value>" + ProductKeyCertificate +"</Value></TokenEntry><TokenEntry><Name>PublishLicense</Name><Value>&lt;?xml version=\"1.0\" encoding=\"utf-8\"?&gt;&lt;rg:licenseGroup xmlns:rg=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\"&gt;&lt;r:license xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\" licenseId=\"{82eb9025-c25f-4dd6-a035-d6994302beb2}\" xmlns:sx=\"urn:mpeg:mpeg21:2003:01-REL-SX-NS\" xmlns:mx=\"urn:mpeg:mpeg21:2003:01-REL-MX-NS\" xmlns:sl=\"http://www.microsoft.com/DRM/XrML2/SL/v2\" xmlns:tm=\"http://www.microsoft.com/DRM/XrML2/TM/v2\"&gt;&lt;r:title&gt;Windows(R) 7 Publishing License (Public)&lt;/r:title&gt;&lt;r:grant&gt;&lt;r:forAll varName=\"account\"&gt;&lt;r:anXmlExpression&gt;/tm:account/tm:identity[@type='urn:msft:tm:identity:hwid' or @type='urn:msft:tm:identity:volume' or @type='urn:msft:tm:identity:oem']&lt;/r:anXmlExpression&gt;&lt;/r:forAll&gt;&lt;r:forAll varName=\"accountKey\"&gt;&lt;r:propertyPossessor&gt;&lt;tm:account varRef=\"account\"/&gt;&lt;r:trustedRootIssuers&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue xmlns=\"http://www.w3.org/2000/09/xmldsig#\"&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;vv2iRRX7Y9YUKoixKYCJ7h635v4qOaaWAVQ/mgXEh39995vw1QGW91GmUZSCYC8bYuhCp2FOSTkeG+UBM/2i3uYmGgpQxgSJfSDBR0E3ujggB2n3AUmoJ3NR1GfdhUuAoLovFP2xSgBJGu9gjBok6rzsYqc4RuqNb82kKKnlfkuPZoIKaMd6TxNcoIZyX3ZAt5mI5duHx8pxkUWl1woLBmo6PljbrnNly3s55kCzT7VoMp6IzIP35K7BEh6ezt/uVf9JDthR6YazBFbEvCgx/NcqRYmFRIUOwR/zcWtldbT1LZJlPJjWBwILxpTmOgvLoqkmO8jFqFcJBIeuUSAoEw==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;/r:trustedRootIssuers&gt;&lt;/r:propertyPossessor&gt;&lt;/r:forAll&gt;&lt;r:forAll varName=\"productId\"&gt;&lt;r:anXmlExpression&gt;/sl:productId/sl:pid&lt;/r:anXmlExpression&gt;&lt;/r:forAll&gt;&lt;r:forAll varName=\"binding\"&gt;&lt;/r:forAll&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue xmlns=\"http://www.w3.org/2000/09/xmldsig#\"&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;v0JgOuEWuaA3INoAK10wY7PLaEhyfjfL5A2joNwBR/3ziJxewXKy5QDzZvD3C9eVdvlSqFCDpZEDUxVWvFFeYKI5YkTeK5x7X4nQPodwZAoTJklTUWpfZNslLYJVMaxRvs8htxKoIbvmssqN4Dhy3Oa7HT80GcOvS95M7UCvXcQ7TjrQUV9QNb0w6WLdMVpuktek1CVi4XQ3ELIHZJhyKAtWNGRN4kxZL9nYyDvZ8be5rlGTuhEsgi1oFqnjzMLYXU4wkF/W8mRedIkvoBu3kCjuwEqsr9P5sIbHowqFX5sRxmTrgwoCXPCtFyXCwu9hO75mvb1I1sCuv8W0gTfMtw==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;r:issue/&gt;&lt;r:grant&gt;&lt;r:forAll varName=\"application\"&gt;&lt;r:anXmlExpression&gt;editionId[@value=\"\" or @value=\"Ultimate\"]&lt;/r:anXmlExpression&gt;&lt;/r:forAll&gt;&lt;r:forAll varName=\"appid\"&gt;&lt;r:propertyPossessor&gt;&lt;tm:application varRef=\"application\"/&gt;&lt;r:trustedRootIssuers&gt;&lt;r:keyHolder&gt;&lt;r:info&gt;&lt;KeyValue xmlns=\"http://www.w3.org/2000/09/xmldsig#\"&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;tajcnLtdaeK0abuL2BpVC7obdfSChnHAx7TSn/37DwbTDegkDkEnbr0YyO/Q5Jluj5QD897+nWW54RDbYYTdNgWjyUpwYEJFXSZtd8LFK2mbIjKfG2HIShp6JJARlrgObR89a1EH716nP3PbJk6PWQa6VfjBzPQUgSVywIRU+OKbnzNbUVmQ/rAN6+AN/8fRmFhyKqOAiV/Np2jBtGNxLXm9ebMdm5cB8/YNrjp5Ey0nyAtYvovb0B7wnQZfolMF+OFiqzWJo2Ze0O7WHsWBHtIlGR3+c/IjxUJAsI7O3U4hncCZdvlC5GORI2YL9YHZgU9guSPLhAybQ3IGg7LBuQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/r:info&gt;&lt;/r:keyHolder&gt;&lt;/r:trustedRootIssuers&gt;&lt;/r:propertyPossessor&gt;&lt;/r:forAll&gt;&lt;r:keyHolder varRef=\"accountKey\"/&gt;&lt;sl:runSoftware/&gt;&lt;sl:appId varRef=\"appid\"/&gt;&lt;r:allConditions&gt;&lt;r:allConditions&gt;&lt;sl:productPolicies xmlns:sl=\"http://www.microsoft.com/DRM/XrML2/SL/v2\"&gt;&lt;sl:priority&gt;400&lt;/sl:priority&gt;&lt;sl:policyStr name=\"Security-SPP-Reserved-Family\" attributes=\"override-only\"&gt;Ultimate&lt;/sl:policyStr&gt;&lt;/sl:productPolicies&gt;&lt;sl:proxyExecutionKey xmlns:sl=\"http://www.microsoft.com/DRM/XrML2/SL/v2\"&gt;&lt;/sl:proxyExecutionKey&gt;&lt;/r:allConditions&gt;&lt;mx:renderer&gt;&lt;sl:binding varRef=\"binding\"/&gt;&lt;sl:productId varRef=\"productId\"/&gt;&lt;/mx:renderer&gt;&lt;/r:allConditions&gt;&lt;/r:grant&gt;&lt;r:allConditions&gt;&lt;sl:businessRules xmlns:sl=\"http://www.microsoft.com/DRM/XrML2/SL/v2\"&gt;&lt;/sl:businessRules&gt;&lt;/r:allConditions&gt;&lt;/r:grant&gt;&lt;r:issuer&gt;&lt;Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"&gt;&lt;SignedInfo&gt;&lt;CanonicalizationMethod Algorithm=\"http://www.microsoft.com/xrml/lwc14n\"/&gt;&lt;SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/&gt;&lt;Reference&gt;&lt;Transforms&gt;&lt;Transform Algorithm=\"urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform\"/&gt;&lt;Transform Algorithm=\"http://www.microsoft.com/xrml/lwc14n\"/&gt;&lt;/Transforms&gt;&lt;DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/&gt;&lt;DigestValue&gt;latzLE7Y8EzdqTUgmh2jIWH9U4A=&lt;/DigestValue&gt;&lt;/Reference&gt;&lt;/SignedInfo&gt;&lt;SignatureValue&gt;MH4IBYFoMdkZt/PhmTxE6D5ZD/RLwHdfFk5vLRsreg8Hd7zqy98kussBlAWpQnAVadLG431nXZcMTbyxLHfMvox7EnkW9rJ+WZkzfW5mS7wsvDddxv3C1Bu7NlPWpz5J13mJsfUgRVBTjO3neObMIo4jgy57JDJqXB4V16SmH4yTdzJ8qhk0DuHZNcx9lV/hR4ezf3872A1mkBWpH1P1VrVhOFPyhYv8T2mrbS9nQoArYOnwANHChtBRc89gxEIr+zsMygHI4R4syxrhS0RFMlgaTi6CNLiHwdlS0dSmVr1nzT4QFSECzYTO4TY+Kp5rQK5wJ+y1As4BT3CydY/GYA==&lt;/SignatureValue&gt;&lt;KeyInfo&gt;&lt;KeyValue&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;tajcnLtdaeK0abuL2BpVC7obdfSChnHAx7TSn/37DwbTDegkDkEnbr0YyO/Q5Jluj5QD897+nWW54RDbYYTdNgWjyUpwYEJFXSZtd8LFK2mbIjKfG2HIShp6JJARlrgObR89a1EH716nP3PbJk6PWQa6VfjBzPQUgSVywIRU+OKbnzNbUVmQ/rAN6+AN/8fRmFhyKqOAiV/Np2jBtGNxLXm9ebMdm5cB8/YNrjp5Ey0nyAtYvovb0B7wnQZfolMF+OFiqzWJo2Ze0O7WHsWBHtIlGR3+c/IjxUJAsI7O3U4hncCZdvlC5GORI2YL9YHZgU9guSPLhAybQ3IGg7LBuQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/KeyInfo&gt;&lt;/Signature&gt;&lt;r:details&gt;&lt;r:timeOfIssue&gt;2010-11-20T13:36:08Z&lt;/r:timeOfIssue&gt;&lt;/r:details&gt;&lt;/r:issuer&gt;&lt;r:otherInfo xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\"&gt;&lt;tm:infoTables xmlns:tm=\"http://www.microsoft.com/DRM/XrML2/TM/v2\"&gt;&lt;tm:infoList tag=\"#global\"&gt;&lt;tm:infoStr name=\"licenseType\"&gt;msft:sl/PL/GENERIC/PUBLIC&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"licenseVersion\"&gt;2.0&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"licensorUrl\"&gt;http://licensing.microsoft.com&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"licenseCategory\"&gt;msft:sl/PL/GENERIC/PUBLIC&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"productSkuId\"&gt;{c619d61c-c2f2-40c3-ab3f-c5924314b0f3}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"privateCertificateId\"&gt;{75d3bbaa-65e0-4bb0-aa85-61ed95ddee95}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"applicationId\"&gt;{55c92734-d682-4d71-983e-d6ec3f16059f}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"productName\"&gt;Windows(R) 7&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"productAuthor\"&gt;Microsoft Corporation&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"productDescription\"&gt;Windows Operating System - Windows(R) 7&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"clientIssuanceCertificateId\"&gt;{4961cc30-d690-43be-910c-8e2db01fc5ad}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"referralData\"&gt;ReferralId=000000;PartnerId=00000000-0000-0000-0000-000000000000&lt;/tm:infoStr&gt;&lt;/tm:infoList&gt;&lt;/tm:infoTables&gt;&lt;/r:otherInfo&gt;&lt;/r:license&gt;&lt;r:license xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\" licenseId=\"{75d3bbaa-65e0-4bb0-aa85-61ed95ddee95}\" xmlns:sx=\"urn:mpeg:mpeg21:2003:01-REL-SX-NS\" xmlns:mx=\"urn:mpeg:mpeg21:2003:01-REL-MX-NS\" xmlns:sl=\"http://www.microsoft.com/DRM/XrML2/SL/v2\" xmlns:tm=\"http://www.microsoft.com/DRM/XrML2/TM/v2\"&gt;&lt;r:title&gt;Windows(R) 7 Publishing License (Private)&lt;/r:title&gt;&lt;r:grant&gt;&lt;r:encryptedGrant&gt;&lt;EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/&gt;&lt;KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"&gt;&lt;EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\"&gt;&lt;EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\" /&gt;&lt;KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"&gt;&lt;KeyValue xmlns=\"http://www.w3.org/2000/09/xmldsig#\"&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;v0JgOuEWuaA3INoAK10wY7PLaEhyfjfL5A2joNwBR/3ziJxewXKy5QDzZvD3C9eVdvlSqFCDpZEDUxVWvFFeYKI5YkTeK5x7X4nQPodwZAoTJklTUWpfZNslLYJVMaxRvs8htxKoIbvmssqN4Dhy3Oa7HT80GcOvS95M7UCvXcQ7TjrQUV9QNb0w6WLdMVpuktek1CVi4XQ3ELIHZJhyKAtWNGRN4kxZL9nYyDvZ8be5rlGTuhEsgi1oFqnjzMLYXU4wkF/W8mRedIkvoBu3kCjuwEqsr9P5sIbHowqFX5sRxmTrgwoCXPCtFyXCwu9hO75mvb1I1sCuv8W0gTfMtw==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/KeyInfo&gt;&lt;CipherData&gt;&lt;CipherValue&gt;W9Umb+v1z+5z2vOMUBaAhZ1LKtk0behRUfIZPS6iTV/PddDBsLWScYNJOrwBiWwiwP3rT4pFsnU1+3sCIkx+iW1xwGohLOLVOFW12Px/5RlZxViNZfI2ADIz8PLNGMIt4j5sw+wM8jDfcLiqAvONVRowz/DJDBDcILr1bX9trIzvBUvKLs2u2wdUrZanLy7iHzY0qQLZMjSH02WKN+kS//VEKCvMo+NmH1f897OSoY3/mfPy39blqBhCcTeOyyzVdvSzp+om3E6lPjknOFGZ41e9YV7zE6rHowGRMXv4Zq4EFJQ3JQGKcmgsa7ZgJPokrdQcVCN9vMoBpG1kEwu5hA==&lt;/CipherValue&gt;&lt;/CipherData&gt;&lt;/EncryptedKey&gt;&lt;/KeyInfo&gt;&lt;CipherData xmlns=\"http://www.w3.org/2001/04/xmlenc#\"&gt;&lt;CipherValue&gt;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&lt;/CipherValue&gt;&lt;/CipherData&gt;&lt;/r:encryptedGrant&gt;&lt;/r:grant&gt;&lt;r:issuer&gt;&lt;Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"&gt;&lt;SignedInfo&gt;&lt;CanonicalizationMethod Algorithm=\"http://www.microsoft.com/xrml/lwc14n\"/&gt;&lt;SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/&gt;&lt;Reference&gt;&lt;Transforms&gt;&lt;Transform Algorithm=\"urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform\"/&gt;&lt;Transform Algorithm=\"http://www.microsoft.com/xrml/lwc14n\"/&gt;&lt;/Transforms&gt;&lt;DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/&gt;&lt;DigestValue&gt;ZtsHovP7OBVt1LI2tHvbgTTqeE0=&lt;/DigestValue&gt;&lt;/Reference&gt;&lt;/SignedInfo&gt;&lt;SignatureValue&gt;Ko1jy16MwvPRJ0qDPUtsX6JBQeGJcO8i579s1oZLAZIpvHIZEOZJybER3SxOuF0piCui1sMzH11/E9J7/UaQqksoMdcDZqiGKbcBTkn4we5K0U/ak4mMI4v2TUQW1yBLHzUYmywNes8e5l/LJeVJMpAClnV2LgSRo+pT6MW0Ghyv/WoxaUBNY4QFHU+Rx4JXeRt+3hSHrF6YrcNR7/75S1exqNfEQZ/h0UGtOx6hexk0M0o5g45zY8wYNqKb8c0S73XwTqVif8HidqkUAjOoNtEep2KYCG0jIvt0OF4JjtzGlSTaTFDiYdZkm6riiMYMA3KtzZm33zjaclDe1TEUTQ==&lt;/SignatureValue&gt;&lt;KeyInfo&gt;&lt;KeyValue&gt;&lt;RSAKeyValue&gt;&lt;Modulus&gt;tajcnLtdaeK0abuL2BpVC7obdfSChnHAx7TSn/37DwbTDegkDkEnbr0YyO/Q5Jluj5QD897+nWW54RDbYYTdNgWjyUpwYEJFXSZtd8LFK2mbIjKfG2HIShp6JJARlrgObR89a1EH716nP3PbJk6PWQa6VfjBzPQUgSVywIRU+OKbnzNbUVmQ/rAN6+AN/8fRmFhyKqOAiV/Np2jBtGNxLXm9ebMdm5cB8/YNrjp5Ey0nyAtYvovb0B7wnQZfolMF+OFiqzWJo2Ze0O7WHsWBHtIlGR3+c/IjxUJAsI7O3U4hncCZdvlC5GORI2YL9YHZgU9guSPLhAybQ3IGg7LBuQ==&lt;/Modulus&gt;&lt;Exponent&gt;AQAB&lt;/Exponent&gt;&lt;/RSAKeyValue&gt;&lt;/KeyValue&gt;&lt;/KeyInfo&gt;&lt;/Signature&gt;&lt;r:details&gt;&lt;r:timeOfIssue&gt;2010-11-20T13:36:08Z&lt;/r:timeOfIssue&gt;&lt;/r:details&gt;&lt;/r:issuer&gt;&lt;r:otherInfo xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\"&gt;&lt;tm:infoTables xmlns:tm=\"http://www.microsoft.com/DRM/XrML2/TM/v2\"&gt;&lt;tm:infoList tag=\"#global\"&gt;&lt;tm:infoStr name=\"licenseType\"&gt;msft:sl/PL/GENERIC/PRIVATE&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"licenseVersion\"&gt;2.0&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"licensorUrl\"&gt;http://licensing.microsoft.com&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"licenseCategory\"&gt;msft:sl/PL/GENERIC/PRIVATE&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"publicCertificateId\"&gt;{82eb9025-c25f-4dd6-a035-d6994302beb2}&lt;/tm:infoStr&gt;&lt;tm:infoStr name=\"clientIssuanceCertificateId\"&gt;{4961cc30-d690-43be-910c-8e2db01fc5ad}&lt;/tm:infoStr&gt;&lt;/tm:infoList&gt;&lt;/tm:infoTables&gt;&lt;/r:otherInfo&gt;&lt;/r:license&gt;&lt;/rg:licenseGroup&gt;</Value></TokenEntry></Values></UseKey><Claims><Values xmlns:q1=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\" soapenc:arrayType=\"q1:TokenEntry[9]\"><TokenEntry><Name>otherInfoPublic.licenseCategory</Name><Value>msft:sl/EUL/ACTIVATED/PUBLIC</Value></TokenEntry><TokenEntry><Name>otherInfoPrivate.licenseCategory</Name><Value>msft:sl/EUL/ACTIVATED/PRIVATE</Value></TokenEntry><TokenEntry><Name>otherInfoPublic.sysprepAction</Name><Value>rearm</Value></TokenEntry><TokenEntry><Name>otherInfoPrivate.sysprepAction</Name><Value>rearm</Value></TokenEntry><TokenEntry><Name>ClientInformation</Name><Value>SystemUILanguageId=2052;UserUILanguageId=2052;GeoId=45</Value></TokenEntry><TokenEntry><Name>ReferralInformation</Name><Value>APPID:55c92734-d682-4d71-983e-d6ec3f16059f:ReferralId=000000;</Value></TokenEntry><TokenEntry><Name>ClientSystemTime</Name><Value>2019-06-19T07:43:32Z</Value></TokenEntry><TokenEntry><Name>otherInfoPublic.secureStoreId</Name><Value>7e64023d-bdee-47ea-982a-3ed823c9d7a3</Value></TokenEntry><TokenEntry><Name>otherInfoPrivate.secureStoreId</Name><Value>7e64023d-bdee-47ea-982a-3ed823c9d7a3</Value></TokenEntry></Values></Claims></RequestSecurityToken></soap:Body></soap:Envelope>";
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://activation.sls.microsoft.com/sllicensing/SLLicense.asmx");
            byte[] bytes;
            bytes = System.Text.Encoding.ASCII.GetBytes(requestXml);
            request.Accept = "text/*";
            request.KeepAlive = true;
            request.ContentType = "text/xml; charset=utf-8";
            request.UserAgent = "SLSSoapClient";
            request.Headers.Add("SOAPAction", "http://microsoft.com/SL/LicensingService/IssueToken");
            request.ContentLength = bytes.Length;
            request.Method = "POST";
            Stream requestStream = request.GetRequestStream();
            requestStream.Write(bytes, 0, bytes.Length);
            requestStream.Close();
            HttpWebResponse response = null;
            var result = "";
            try
            {
                response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    Stream responseStream = response.GetResponseStream();
                    result = new StreamReader(responseStream).ReadToEnd();
                }
            }
            catch (WebException ex)
            {
                string exMessage = ex.Message;
                if (ex.Response != null)
                {
                    var responseReader = new StreamReader(ex.Response.GetResponseStream());
                    result = responseReader.ReadToEnd();
                }
            }
            using (XmlReader soapReader = XmlReader.Create(new StringReader(result)))
            {
                soapReader.ReadToFollowing("HRESULT");
                string responseXML = soapReader.ReadElementContentAsString();
                return responseXML;
            }
        }

        public static string GetErrorCoderWin81(string pid)
        {

            string requestXml = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\"><soap:Body><RequestSecurityToken xmlns=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\"><TokenType>ProductActivation</TokenType><RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</RequestType><UseKey><Values xmlns:q1=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\" soapenc:arrayType=\"q1:TokenEntry[1]\"><TokenEntry><Name>PublishLicense</Name><Value>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</Value></TokenEntry></Values></UseKey><Claims><Values xmlns:q1=\"http://schemas.xmlsoap.org/ws/2004/04/security/trust\" soapenc:arrayType=\"q1:TokenEntry[17]\"><TokenEntry><Name>SessionKey</Name><Value>IfLY6rBu3vP7mJ+p8E+J8CcphSUf4BfKULNYgzC7qv+LN2MOcWXkltsrL1BzI7lYH80posi03Xtu2rDtga7zU8bJjN5MaX1Y4WN86qvUTeF+HQpmRbqWLrGkD4MvSFiBqQF95Y5IUIWYnub9GG5KblR0vi54+8CDyR3q5POX+UCyuPaadNeW5d2UYo7aphrHdOIKf2clxqsZO1bPlNqfkhtFYd1lJjM1J92Umb5K6cKVCnk02hSryHmjDUnpdq162OXyVi453IjsnSCGf2j73x5LR33KQC7wRgD/NfGohOdcQmKFq1m82vSJN1GrLrFQYmy2ixLB0RC200zp2kAC6A==</Value></TokenEntry><TokenEntry><Name>BindingType</Name><Value>+K3HPxtE5zsqZwX7eTC6ZTRClq6pCrkPY60dzEesefw=</Value></TokenEntry><TokenEntry><Name>Binding</Name><Value>wdMN30H8sF3XbtO1uSmAQpXarpWfz9VoR9m+Lo1cvHbJ/wVph7x21pVHfXMW4IcU8KQqjMjFfBQDCahCy/Vzug==</Value></TokenEntry><TokenEntry><Name>ProductKey</Name><Value>ufQAC1HY6NyR6WExjuSlDm0D76BjqWcj5b0M7LK/B8I=</Value></TokenEntry><TokenEntry><Name>ProductKeyType</Name><Value>+K3HPxtE5zsqZwX7eTC6ZXX7FsGjArspyTW7cBb/fZQ=</Value></TokenEntry><TokenEntry><Name>ProductKeyActConfigId</Name><Value>EA53IzCpwgsawUd4yGlyXiFGKQUb2apAypaSn+OoW3fcB9sHZovrezBH9x6BditMI5JEf0kY7R9ZajSLRHfyMPwWw9gFqXVUoMnkbC0KyDI=</Value></TokenEntry><TokenEntry><Name>SppSvcVersion</Name><Value>agLGQGQ47KlQy+2Evb7C1Q==</Value></TokenEntry><TokenEntry><Name>otherInfoPublic.licenseCategory</Name><Value>33SHcksuxFRyyB4Si4mqeaaQGoKuKGZRPooeQPQtXtk=</Value></TokenEntry><TokenEntry><Name>otherInfoPrivate.licenseCategory</Name><Value>33SHcksuxFRyyB4Si4mqeTb1NUaDwzrPoJ0KZYC7hkM=</Value></TokenEntry><TokenEntry><Name>otherInfoPublic.sysprepAction</Name><Value>8y/LJrXGTXchI6mhRHpjlA==</Value></TokenEntry><TokenEntry><Name>otherInfoPrivate.sysprepAction</Name><Value>8y/LJrXGTXchI6mhRHpjlA==</Value></TokenEntry><TokenEntry><Name>ClientInformation</Name><Value>1wtG2KWCXHEA/9xjU0rzc2NWfYMRmknNJL/XvkdwcgaMysqD3RqCSMJT2XmUt5UmEiXVvxu3NYl9j4Iu164now==</Value></TokenEntry><TokenEntry><Name>ReferralInformation</Name><Value>i0Jl7JHdnVyWZtHfLM6+NK2IMDbRdXDllrqWfSU+jmWQzNBHIEdZMbjonR5+bqjnnZMC5BrGffNcrbS4GwPi3A==</Value></TokenEntry><TokenEntry><Name>ClientSystemTime</Name><Value>DCaQS1Lx6Kxki+QXZXqna6dTVD5U2uZfrkWUwBx06Us=</Value></TokenEntry><TokenEntry><Name>ClientSystemTimeUtc</Name><Value>DCaQS1Lx6Kxki+QXZXqna6dTVD5U2uZfrkWUwBx06Us=</Value></TokenEntry><TokenEntry><Name>otherInfoPublic.secureStoreId</Name><Value>yTH9vmXD4vnlU3NiEPLowwaxTYzOXg7U4AMdG9XxZ6opPaXlyPNlX4HHYzTIrz0M</Value></TokenEntry><TokenEntry><Name>otherInfoPrivate.secureStoreId</Name><Value>yTH9vmXD4vnlU3NiEPLowwaxTYzOXg7U4AMdG9XxZ6opPaXlyPNlX4HHYzTIrz0M</Value></TokenEntry></Values></Claims></RequestSecurityToken></soap:Body></soap:Envelope>";
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://activation-v2.sls.microsoft.com/SLActivateProduct/SLActivateProduct.asmx?configextension=Retail");
            byte[] bytes;
            bytes = System.Text.Encoding.ASCII.GetBytes(requestXml);
            request.Accept = "text/*";
            request.KeepAlive = true;
            request.ContentType = "text/xml; charset=utf-8";
            request.UserAgent = "SLSSoapClient";
            request.Headers.Add("SOAPAction", "http://microsoft.com/SL/ProductActivationService/IssueToken");
            request.ContentLength = bytes.Length;
            request.Method = "POST";
            Stream requestStream = request.GetRequestStream();
            requestStream.Write(bytes, 0, bytes.Length);
            requestStream.Close();
            HttpWebResponse response = null;
            var result = "";
            try
            {
                response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    Stream responseStream = response.GetResponseStream();
                    result = new StreamReader(responseStream).ReadToEnd();
                }
            }
            catch (WebException ex)
            {
                string exMessage = ex.Message;
                if (ex.Response != null)
                {
                    var responseReader = new StreamReader(ex.Response.GetResponseStream());
                    result = responseReader.ReadToEnd();
                }
            }
            using (XmlReader soapReader = XmlReader.Create(new StringReader(result)))
            {
                soapReader.ReadToFollowing("HRESULT");
                string responseXML = soapReader.ReadElementContentAsString();
                return responseXML;
            }
        }
        /// <summary>
        /// //////            Console.WriteLine(GetCount("XXXXX-00172-033-000046-03-1045-8400.0000-1952012"));
        ///////////////Console.ReadKey();
        /// </summary>
        private static readonly byte[] bPrivateKey = new byte[] {
            0xfe, 0x31, 0x98, 0x75, 0xfb, 0x48, 0x84, 0x86, 0x9c, 0xf3, 0xf1, 0xce, 0x99, 0xa8, 0x90, 0x64,
            0xab, 0x57, 0x1f, 0xca, 0x47, 0x04, 0x50, 0x58, 0x30, 0x24, 0xe2, 0x14, 0x62, 0x87, 0x79, 0xa0,
         };
        public static string GetCount(string pid)
        {
            // XML Namespace
            const string uri = "http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0";

            // Create new XML Document
            XmlDocument xmlDoc = new XmlDocument();

            // Create Root Element
            XmlElement rootElement = xmlDoc.CreateElement("ActivationRequest", uri);
            xmlDoc.AppendChild(rootElement);

            // Create VersionNumber Element
            XmlElement versionNumber = xmlDoc.CreateElement("VersionNumber", rootElement.NamespaceURI);
            versionNumber.InnerText = "2.0";
            rootElement.AppendChild(versionNumber);

            // Create RequestType Element
            XmlElement requestType = xmlDoc.CreateElement("RequestType", rootElement.NamespaceURI);
            requestType.InnerText = "2";
            rootElement.AppendChild(requestType);

            // Create Requests Group Element
            XmlElement requestsGroupElement = xmlDoc.CreateElement("Requests", rootElement.NamespaceURI);

            // Create Request Element
            XmlElement requestElement = xmlDoc.CreateElement("Request", requestsGroupElement.NamespaceURI);

            // Add PID as Request Element
            XmlElement pidEntry = xmlDoc.CreateElement("PID", requestElement.NamespaceURI);
            pidEntry.InnerText = pid.Replace("00000", "55041");
            requestElement.AppendChild(pidEntry);

            // Add Request Element to Requests Group Element
            requestsGroupElement.AppendChild(requestElement);

            // Add Requests and Request to XML Document
            rootElement.AppendChild(requestsGroupElement);

            // Get Unicode Byte Array of XML Document
            byte[] byteXml = Encoding.Unicode.GetBytes(xmlDoc.InnerXml);

            // Convert Byte Array to Base64
            string base64Xml = Convert.ToBase64String(byteXml);

            // Compute Digest of the Base 64 XML Bytes
            HMACSHA256 hmacsha256 = new HMACSHA256()
            {
                Key = bPrivateKey
            };
            string digest = Convert.ToBase64String(hmacsha256.ComputeHash(byteXml));

            // Create SOAP Envelope for Web Request
            string form = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><soap:Body><BatchActivate xmlns=\"http://www.microsoft.com/BatchActivationService\"><request><Digest>REPLACEME1</Digest><RequestXml>REPLACEME2</RequestXml></request></BatchActivate></soap:Body></soap:Envelope>";
            form = form.Replace("REPLACEME1", digest);
            // Put your Digest value (BASE64 encoded)
            form = form.Replace("REPLACEME2", base64Xml);
            // Put your Base64 XML value (BASE64 encoded)
            XmlDocument soapEnvelopeXml = new XmlDocument();
            soapEnvelopeXml.LoadXml(form);

            // Create Web Request
            HttpWebRequest webRequest__1 = (HttpWebRequest)WebRequest.Create("https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx");
            webRequest__1.Method = "POST";
            webRequest__1.ContentType = "text/xml; charset=\"utf-8\"";
            webRequest__1.Headers.Add("SOAPAction", "http://www.microsoft.com/BatchActivationService/BatchActivate");

            // Insert SOAP Envelope into Web Request
            using (Stream stream = webRequest__1.GetRequestStream())
            {
                soapEnvelopeXml.Save(stream);
            }

            // Begin Async call to Web Request
            IAsyncResult asyncResult = webRequest__1.BeginGetResponse(null/* TODO Change to default(_) if this is not a reference type */, null/* TODO Change to default(_) if this is not a reference type */);

            // Suspend Thread until call is complete
            asyncResult.AsyncWaitHandle.WaitOne();

            // Get the Response from the completed Web Request
            string soapResult;
            using (WebResponse webResponse = webRequest__1.EndGetResponse(asyncResult))
            {
                using (StreamReader rd = new StreamReader(webResponse.GetResponseStream()))
                {
                    soapResult = rd.ReadToEnd();
                }
            }

            // Parse the ResponseXML from the Response
            using (XmlReader soapReader = XmlReader.Create(new StringReader(soapResult)))
            {
                // Read ResponseXML Value
                soapReader.ReadToFollowing("ResponseXml");
                string responseXML = soapReader.ReadElementContentAsString();

                // Remove HTML Entities from ResponseXML
                responseXML = responseXML.Replace("&gt;", ">");
                responseXML = responseXML.Replace("&lt;", "<");

                // Change Encoding Value in ResponseXML
                responseXML = responseXML.Replace("utf-16", "utf-8");

                // Read Fixed ResponseXML Value as XML
                using (XmlReader reader = XmlReader.Create(new StringReader(responseXML)))
                {
                    try
                    {
                        reader.ReadToFollowing("ActivationRemaining");
                        string count = reader.ReadElementContentAsString();

                        if (Convert.ToInt32(count) < 0)
                        {
                            reader.ReadToFollowing("ErrorCode");
                            string error = reader.ReadElementContentAsString();

                            if (error == "0x67")
                                return "0 (Blocked)";
                        }
                        return count;
                    }
                    catch
                    {

                    }

                    return null;
                }
            }
        }


        //string cid = GetCryptoID(PKeyPath, "{" + aid + "}").Trim();
        static string GetCryptoID(string pkey, string aid)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(pkey);
            MemoryStream stream = new MemoryStream(Convert.FromBase64String(doc.GetElementsByTagName("tm:infoBin")[0].InnerText));
            doc.Load(stream);
            XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("pkc", "http://www.microsoft.com/DRM/PKEY/Configuration/2.0");
            try
            {
                XmlNode node = doc.SelectSingleNode("/pkc:ProductKeyConfiguration/pkc:Configurations/pkc:Configuration[pkc:ActConfigId='" + aid + "']", ns);
                if (node == null)
                {
                    node = doc.SelectSingleNode("/pkc:ProductKeyConfiguration/pkc:Configurations/pkc:Configuration[pkc:ActConfigId='" + aid.ToUpper() + "']", ns);
                }
                if (node.HasChildNodes)
                {
                    return node.ChildNodes[1].InnerText;
                }
                return "Not Found";
            }
            catch (Exception)
            {
                return "Not Found";
            }
            finally
            {
                stream.Dispose();
            }
        }
  
    }
}
