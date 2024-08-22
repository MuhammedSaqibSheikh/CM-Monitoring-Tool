using System;
using System.Configuration;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace Encryption_Module
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            this.CenterToScreen();
        }

        public static string EncryptPassword(string toEncrypt, bool useHashing)
        {
            byte[] keyArray;
            byte[] toEncryptArray = Encoding.UTF8.GetBytes(toEncrypt);
            string key = "WETHEPEOPLEOFINDIAHAVING";
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
                tdes.Padding = PaddingMode.PKCS7;

                ICryptoTransform cTransform = tdes.CreateEncryptor();
                byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

                return Convert.ToBase64String(resultArray, 0, resultArray.Length);
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            textBox2.Text = EncryptPassword(textBox1.Text, false);
        }
    }
}
