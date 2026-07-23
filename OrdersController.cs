using System;
using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Web.Mvc;

namespace Corp.Shop.Controllers
{
    public class OrdersController : Controller
    {
        // VULN 1: Hardcoded ASP.NET machineKey material committed to source.
        // With the validation/decryption keys known, an attacker can forge a
        // valid __VIEWSTATE (MAC passes) and reach the ViewState deserializer => RCE.
        private const string ValidationKey =
            "C50B3C89CB21F4F1422FF158A5B42D0E8DB8CB5CDA1742572A487D9401E3400267682B202B746511891C1BAF47F8D25C07F6C39A104D6E31294060DA2C6F0";
        private const string DecryptionKey =
            "8A9BE8FD67AF6979E7D20198CFEA50DD3D3799C77AF2B72F";

        // VULN 2: Insecure Deserialization — BinaryFormatter on untrusted request
        // bytes enables gadget-chain remote code execution. BinaryFormatter is
        // unsafe by design and cannot be made safe.
        [HttpPost]
        public ActionResult Restore()
        {
            var fmt = new BinaryFormatter();
            var order = fmt.Deserialize(Request.InputStream); // RCE
            return Json(new { restored = order.ToString() });
        }

        // VULN 3: Weak Cryptography — DES (56-bit) in ECB mode with a hardcoded
        // key. DES is brute-forceable and ECB leaks plaintext structure.
        public string Encrypt(string data)
        {
            using (var des = DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Key = Encoding.ASCII.GetBytes("8bytekey");
                var enc = des.CreateEncryptor();
                var bytes = Encoding.UTF8.GetBytes(data);
                var ct = enc.TransformFinalBlock(bytes, 0, bytes.Length);
                return Convert.ToBase64String(ct);
            }
        }
    }
}
