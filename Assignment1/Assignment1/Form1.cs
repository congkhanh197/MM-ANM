using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;
using Microsoft.VisualBasic;
using System.Diagnostics;
using System.Xml;

namespace Assignment1
{
    public partial class Form1 : Form
    {

        private delegate void BtnEncryptDecryptDelegate();
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            this.cbAESMode.SelectedIndex = 0;
            this.cbDESMode.SelectedIndex = 0;
            this.cbHFileOrText.SelectedIndex = 0;
            this.cbHashAlg.SelectedIndex = 0;
            this.cbAESSelectKeyLength.SelectedIndex = 0;
            this.cbRSAKeyLength.SelectedIndex = 0;
        }

        #region AES

        private void AESAlgorithm(String inputFile, String OutputFile, String keys, bool isEncrypt, String mode)
        {
            try
            {
                FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
                FileStream fsCiperText = new FileStream(OutputFile, FileMode.Create, FileAccess.Write);

                fsCiperText.SetLength(0);
                int numberBytesRead = 10485760;//10MB
                byte[] bin = new byte[numberBytesRead];
                long rdlen = 0;
                long totlen = fsInput.Length;
                int len;

                pgbAES.Minimum = 0;
                pgbAES.Maximum = 100;

                AesCryptoServiceProvider AESProvider = new AesCryptoServiceProvider();

                try
                {
                    AESProvider.Key = Convert.FromBase64String(keys);
                    AESProvider.IV = ASCIIEncoding.ASCII.GetBytes(keys.Substring(0, 16));
                }
                catch (Exception ioex)
                {
                    MessageBox.Show("Failed: " + ioex.Message);
                    return;
                }

                if (mode == "ECB") AESProvider.Mode = CipherMode.ECB;
                else if (mode == "CBC") AESProvider.Mode = CipherMode.CBC;
                else if (mode == "CFB") AESProvider.Mode = CipherMode.CFB;

                CryptoStream cryptStream;
                if (isEncrypt)
                    cryptStream = new CryptoStream(fsCiperText, AESProvider.CreateEncryptor(), CryptoStreamMode.Write);
                else
                    cryptStream = new CryptoStream(fsCiperText, AESProvider.CreateDecryptor(), CryptoStreamMode.Write);

                //Read from the input file, then encrypt and write to the output file.
                while (rdlen < totlen)
                {
                    len = fsInput.Read(bin, 0, numberBytesRead);
                    cryptStream.Write(bin, 0, len);
                    rdlen = rdlen + len;

                    this.lblAESProg.Text = "Tên tệp xử lý : " + Path.GetFileName(inputFile);
                    this.lblAESProg.Refresh();
                    this.lblAESProgPercent.Text = ((long)(rdlen * 100) / totlen).ToString() + " %";
                    this.lblAESProgPercent.Refresh();

                    pgbAES.Value = (int)((rdlen * 100) / totlen);

                }

                if (pgbAES.IsHandleCreated && rbAESInputFile.Checked)
                {
                    System.Diagnostics.Process prc = new System.Diagnostics.Process();
                    prc.StartInfo.FileName = Path.GetDirectoryName(txtAESOutput.Text);
                    prc.Start();
                }

                cryptStream.Close();
                fsInput.Close();
                fsCiperText.Close();
            }
            catch (Exception ioex)
            {
                MessageBox.Show("Failed: " + ioex.Message);
            }

        }

        private void btnAESEncryptClick()
        {
            if (InvokeRequired)
            {
                this.Invoke(new MethodInvoker(btnAESEncryptClick));
                return;
            }

            if (Strings.Len(Strings.Trim(txtAESInput.Text)) != 0 && Strings.Len(Strings.Trim(txtAESKey.Text)) != 0 && Strings.Len(Strings.Trim(cbAESMode.Text)) != 0)
            {
                Stopwatch sw = Stopwatch.StartNew();
                sw.Start();
                enabledOrDisableAESButtons(false);

                string inputFileName, outputFileName, mode, key;
                inputFileName = txtAESInput.Text;

                key = txtAESKey.Text;

                if (key.Length < 8)
                {
                    MessageBox.Show("Bạn vui lòng nhập độ dài KEY phải lớn hơn hoặc bằng 8!");
                    enabledOrDisableAESButtons(true);
                    return;
                }
                mode = cbAESMode.Text;

                if (key.Length != 32 && key.Length != 24 && key.Length != 44)
                {
                    for (int i = 0; i < 32 - (txtAESKey.Text.Length); i++)
                        key += "t";
                }

                if (key.Length == 24) key = key.Substring(0, 22) + "==";
                if (key.Length == 44) key = key.Substring(0, 43) + "=";


                if (this.rbAESInputFile.Checked)
                {
                    outputFileName = this.txtAESOutput.Text;
                    AESAlgorithm(inputFileName, outputFileName, key, true, mode);
                }
                else
                {
                    string[] filePaths = Directory.GetFiles(inputFileName);

                    filePaths = Directory.GetFiles(inputFileName, "*.*", SearchOption.AllDirectories);

                    if (filePaths.Length == 0 || (filePaths.Length == 1 && (Path.GetFileName(filePaths[0]) == "Thumbs.db")))
                    {
                        MessageBox.Show("Thư mục hiện tại bạn chọn là thư mục rỗng ! Vui lòng chọn lại thư mục khác !");
                        enabledOrDisableAESButtons(true);
                        return;
                    }

                    for (int i = 0; i < filePaths.Length; i++)
                    {
                        if (Path.GetFileName(filePaths[i]) != "Thumbs.db")
                        {
                            string outputFile = filePaths[i].Replace(this.txtAESInput.Text, this.txtAESOutput.Text);
                            string outputDir = Path.GetDirectoryName(outputFile);
                            if (!Directory.Exists(outputDir))
                                Directory.CreateDirectory(outputDir);
                            AESAlgorithm(filePaths[i], outputFile, key, true, mode);
                        }
                    }

                }
                enabledOrDisableAESButtons(true);
                sw.Stop();
                double elapsedMs = sw.Elapsed.TotalMilliseconds / 1000;
                MessageBox.Show("Tổng thời gian chương trình đã thực thi là : " + elapsedMs.ToString() + " s");
            }
            else
            {
                MessageBox.Show("Dữ liệu không đủ để chương trình mã hóa ! Vui lòng cung cấp đầy đủ dữ liệu !");
            }
        }

        private void btnAESDecryptClick()
        {
            if (InvokeRequired)
            {
                this.Invoke(new MethodInvoker(btnAESDecryptClick));
                return;
            }

            if (Strings.Len(Strings.Trim(txtAESInput.Text)) != 0 &&
            Strings.Len(Strings.Trim(txtAESKey.Text)) != 0 &&
            Strings.Len(Strings.Trim(cbAESMode.Text)) != 0
            )
            {
                //Calculator time execution....
                Stopwatch sw = Stopwatch.StartNew();
                sw.Start();
                enabledOrDisableAESButtons(false);
                string inputFileName, mode, keySize, key;
                string outputFileName = this.txtAESOutput.Text;
                inputFileName = txtAESInput.Text;
                
                key = txtAESKey.Text;

                if (key.Length < 8)
                {
                    MessageBox.Show("Độ dài KEY phải lớn hơn hoặc bằng 8!");
                    enabledOrDisableAESButtons(true);
                    return;
                }

                mode = cbAESMode.Text;

                if (key.Length != 32 && key.Length != 24 && key.Length != 44)
                    for (int i = 0; i < 32 - txtAESKey.Text.Length; i++)
                        key += "t";

                if (key.Length == 24) key = key.Substring(0, 22) + "==";
                if (key.Length == 44) key = key.Substring(0, 43) + "=";
                if (this.rbAESInputFile.Checked)
                {
                    AESAlgorithm(inputFileName, outputFileName, key, false, mode);
                }
                else
                {

                    string[] filePaths = Directory.GetFiles(inputFileName, "*.*");

                    filePaths = Directory.GetFiles(inputFileName, "*.*", SearchOption.AllDirectories);

                    if (filePaths.Length == 0 || (filePaths.Length == 1 && (Path.GetFileName(filePaths[0]) == "Thumbs.db")))
                    {
                        MessageBox.Show("Thư mục hiện tại không có chứa file !");
                        enabledOrDisableAESButtons(true);
                        return;
                    }

                    for (int i = 0; i < filePaths.Length; i++)
                    {
                        if (Path.GetFileName(filePaths[i]) != "Thumbs.db")
                        {
                            string outputFile = filePaths[i].Replace(this.txtAESInput.Text, this.txtAESOutput.Text);
                            string outputDir = Path.GetDirectoryName(outputFile);
                            if (!Directory.Exists(outputDir))
                                Directory.CreateDirectory(outputDir);
                            AESAlgorithm(filePaths[i], outputFile, key, false, mode);
                        }
                    }

                }
                enabledOrDisableAESButtons(true);
                sw.Stop();
                double elapsedMs = sw.Elapsed.TotalMilliseconds / 1000;
                MessageBox.Show("Tổng thời gian chương trình đã thực thi là : " + elapsedMs.ToString() + " s");
            }
            else
            {
                MessageBox.Show("Dữ liệu không đủ để chương trình thực thi ! Vui lòng cung cấp đầy đủ dữ liệu !");
            }
        }

        private void btnAESGenKey_Click(object sender, EventArgs e)
        {
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            if (Microsoft.VisualBasic.Strings.Len(Strings.Trim(cbAESSelectKeyLength.Text)) != 0)
            {
                if (cbAESSelectKeyLength.Text == "128bits")
                    aes.KeySize = 128;
                else if (cbAESSelectKeyLength.Text == "192bits")
                    aes.KeySize = 192;
                else aes.KeySize = 256;

                aes.GenerateKey();
                txtAESKey.Text = Convert.ToBase64String(aes.Key);
            }
        }

        private void btnAESInput_Click(object sender, EventArgs e)
        {
            if (rbAESInputFile.Checked)
            {
                OpenFileDialog ofd = new OpenFileDialog();
                ofd.Filter = "All Files (*.*)|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    this.txtAESInput.Text = ofd.FileName;
                    rbAESEncrypt_CheckedChanged(null, null);
                    rbAESDecrypt_CheckedChanged(null, null);
                }
            }
            else
            {
                FolderBrowserDialog fbd = new FolderBrowserDialog();
                if (fbd.ShowDialog() == DialogResult.OK)
                {
                    this.txtAESInput.Text = fbd.SelectedPath;
                    rbAESEncrypt_CheckedChanged(null, null);
                    rbAESDecrypt_CheckedChanged(null, null);
                }
            }
        }

        private void btnAESOutput_Click(object sender, EventArgs e)
        {
            if (Strings.Len(Strings.Trim(txtAESOutput.Text)) > 0)
            {
                try
                {
                    System.Diagnostics.Process prc = new System.Diagnostics.Process();
                    if (!rbAESInputFile.Checked)
                        prc.StartInfo.FileName = txtAESOutput.Text;
                    else
                        prc.StartInfo.FileName = Path.GetDirectoryName(txtAESOutput.Text);

                    prc.Start();
                }
                catch (Exception ioex)
                {
                    MessageBox.Show("Failed: " + ioex.Message);
                }
            }
            else
            {
                MessageBox.Show("Thư mục không mở được , do quá trình mã hóa hoặc giải mã chưa thực thi!");
            }
        }

        private void btnAESEncrypt_Click(object sender, EventArgs e)
        {
            if (rbAESEncrypt.Checked)
            {
                BtnEncryptDecryptDelegate s = new BtnEncryptDecryptDelegate(btnAESEncryptClick);
                s.BeginInvoke(null, null);
            }
            else
            {
                BtnEncryptDecryptDelegate s = new BtnEncryptDecryptDelegate(btnAESDecryptClick);
                s.BeginInvoke(null, null);
            }
            
        }

        private void enabledOrDisableAESButtons(bool isEnable)
        {

            this.btnAESReset.Enabled = isEnable;
            this.btnAESOutput.Enabled = isEnable;
            //this.tbOutput.Enabled = isEnable;
            this.btnAESEncrypt.Enabled = isEnable;
            this.btnAESGenKey.Enabled = isEnable;
        }

        private void btnAESReset_Click(object sender, EventArgs e)
        {
            this.txtAESKey.Clear();
            this.txtAESInput.Clear();
            this.txtAESOutput.Clear();
            this.cbAESMode.Text = "CBC";
            this.lblAESProg.Text = "";
            this.lblAESProg.Update();
            this.lblAESProgPercent.Text = "0%";
            this.lblAESProgPercent.Update();

            this.cbAESSelectKeyLength.Text = "256bits";
            if (this.pgbAES.Value > 0)
                this.pgbAES.Value = 0;
        }
        
        private void rbAESEncrypt_CheckedChanged(object sender, EventArgs e)
        {
            if (this.rbAESEncrypt.Checked)
            {
                this.btnAESEncrypt.Text = "Encrypt";
                if (this.rbAESInputFile.Checked)
                {
                    if (!String.IsNullOrEmpty(this.txtAESInput.Text))
                    {
                        string ext = Path.GetExtension(this.txtAESInput.Text);
                        this.txtAESOutput.Text = this.txtAESInput.Text.Insert(this.txtAESInput.Text.Length - ext.Length, "_encrypted");
                    }
                }
                else
                {
                    if (!String.IsNullOrEmpty(this.txtAESInput.Text))
                        this.txtAESOutput.Text = this.txtAESInput.Text + "_encrypted";
                }
            }
        }

        private void rbAESDecrypt_CheckedChanged(object sender, EventArgs e)
        {
            if (this.rbAESDecrypt.Checked)
            {
                this.btnAESEncrypt.Text = "Decrypt";
                if (this.rbAESInputFile.Checked)
                {
                    if (!String.IsNullOrEmpty(this.txtAESInput.Text))
                    {
                        string fileName = Path.GetFileNameWithoutExtension(this.txtAESInput.Text);
                        if (fileName.Contains("_encrypted"))
                        {
                            this.txtAESOutput.Text = Path.GetDirectoryName(this.txtAESInput.Text) + "\\"
                           + fileName.Replace("_encrypted", "")
                           + Path.GetExtension(this.txtAESInput.Text);
                        }
                        else
                        {
                            this.txtAESOutput.Text = Path.GetDirectoryName(this.txtAESInput.Text) + "\\"
                           + fileName.Insert(fileName.Length, "_decrypted")
                           + Path.GetExtension(this.txtAESInput.Text);
                        }
                       
                    }
                }
                else
                {
                    string[] dirs = this.txtAESInput.Text.Split('\\');
                    if (dirs.Last().Contains("_encrypted"))
                    {
                        this.txtAESOutput.Text = Path.GetDirectoryName(this.txtAESInput.Text) + "\\" + dirs.Last().Replace("_encrypted", "");
                    }
                    else
                    {
                        this.txtAESOutput.Text = this.txtAESInput.Text + "_decrypted";
                    }
                    
                }
                
            }
        }

        #endregion

        #region DES

        void DESAlgorithm(string sInputFilename, string sOutputFilename, string sKey, string mode, bool isEncrypt)
        {
            try
            {
                byte[] bytes = Convert.FromBase64String(sKey); //Key 8 bytes = 64bits.

                //Open the input file and create the output file.
                FileStream fsInput = new FileStream(sInputFilename, FileMode.Open, FileAccess.Read);
                FileStream fsOutput = new FileStream(sOutputFilename, FileMode.OpenOrCreate, FileAccess.Write);
                fsOutput.SetLength(0);

                long totlen = fsInput.Length;           // Get file size.
                int numberBytesRead = 10485760, len;     // Each reading 10MB.
                byte[] bin = new byte[numberBytesRead];
                long rdlen = 0;


                //Set parameter for progress bar.
                pgbDES.Minimum = 0;
                pgbDES.Maximum = 100;

                //DES 
                DESCryptoServiceProvider DES = new DESCryptoServiceProvider();

                //Set mode for DES Algorithm.
                if (mode == "ECB") DES.Mode = CipherMode.ECB;
                else if (mode == "CBC") DES.Mode = CipherMode.CBC;
                else if (mode == "CFB") DES.Mode = CipherMode.CFB;


                CryptoStream encStream;

                if (isEncrypt)
                    encStream = new CryptoStream(fsOutput, DES.CreateEncryptor(bytes, bytes), CryptoStreamMode.Write);
                else
                    encStream = new CryptoStream(fsOutput, DES.CreateDecryptor(bytes, bytes), CryptoStreamMode.Write);


                /* Read from the input file , 
                 * each reading "numberBytesRead", 
                 * then encrypted and written to the output file.
                 */
                while (rdlen < totlen)
                {
                    len = fsInput.Read(bin, 0, numberBytesRead);//Each reading 100bytes
                    encStream.Write(bin, 0, len);
                    rdlen = rdlen + len;

                    this.lblDESProg.Text = "Tên tệp xử lý : " + Path.GetFileName(sInputFilename);
                    this.lblDESProg.Refresh();
                    this.lblDESProgPercent.Text = ((long)(rdlen * 100) / totlen).ToString() + " %";
                    this.lblDESProgPercent.Refresh();

                    pgbDES.Value = (int)((rdlen * 100) / totlen);
                }

                encStream.Close();
                fsOutput.Close();
                fsInput.Close();
            }
            catch (Exception e)
            {
                MessageBox.Show("Failed : " + e.Message);
            }
        }

        private void btnDESEncryptClick()
        {
            if (InvokeRequired)
            {
                this.Invoke(new MethodInvoker(btnDESEncryptClick));
                return;
            }


            if (Strings.Len(Strings.Trim(txtDESInput.Text)) != 0 && Strings.Len(Strings.Trim(txtDESKey.Text)) != 0 && Strings.Len(Strings.Trim(cbDESMode.Text)) != 0)
            {
                Stopwatch sw = Stopwatch.StartNew();
                sw.Start();
                enabledOrDisableDESButtons(false);

                string inputFileName, outputFileName, mode, key;

                key = txtDESKey.Text;                         //get Key. (base64String)
                if (key.Length < 8)
                {
                    MessageBox.Show("Bạn vui lòng nhập độ dài KEY phải lớn hơn hoặc bằng 8!");
                    enabledOrDisableDESButtons(true);
                    return;
                }
                mode = cbDESMode.Text;                 //get Mode.

                if (key.Length >= 8 && key.Length < 12)
                    for (int i = 0; i < 12 - txtDESKey.Text.Length; i++)
                        key += "t";

                if (key.Length >= 12) key = key.Substring(0, 11) + "=";

                inputFileName = txtDESInput.Text;             //get Input file.

                if (this.rbDESInputFile.Checked)
                {
                    outputFileName = txtDESOutput.Text;
                    DESAlgorithm(inputFileName, outputFileName, key, mode, true);
                }
                else
                {
                    string[] filePaths = Directory.GetFiles(inputFileName);

                    filePaths = Directory.GetFiles(inputFileName, "*.*", SearchOption.AllDirectories);

                    if (filePaths.Length == 0 || (filePaths.Length == 1 && (Path.GetFileName(filePaths[0]) == "Thumbs.db")))
                    {
                        MessageBox.Show("Thư mục hiện tại bạn chọn là thư mục rỗng ! Vui lòng chọn lại thư mục khác !");
                        enabledOrDisableDESButtons(true);
                        return;
                    }

                    for (int i = 0; i < filePaths.Length; i++)
                    {
                        if (Path.GetFileName(filePaths[i]) != "Thumbs.db")
                        {
                            string outputFile = filePaths[i].Replace(this.txtDESInput.Text, this.txtDESOutput.Text);
                            string outputDir = Path.GetDirectoryName(outputFile);
                            if (!Directory.Exists(outputDir))
                                Directory.CreateDirectory(outputDir);
                            DESAlgorithm(filePaths[i], outputFile, key, mode, true);
                        }
                    }

                }

                enabledOrDisableDESButtons(true);

                sw.Stop();
                double elapsedMs = sw.Elapsed.TotalMilliseconds / 1000;
                MessageBox.Show("Tổng thời gian chương trình đã thực thi là : " + elapsedMs.ToString() + " s");
            }
            else
            {
                MessageBox.Show("Dữ liệu không đủ để chương trình mã hóa ! Vui lòng cung cấp đầy đủ dữ liệu !");
            }
        }

        private void btnDESDecryptClick()
        {
            if (InvokeRequired)
            {
                this.Invoke(new MethodInvoker(btnDESDecryptClick));
                return;
            }

            if (Strings.Len(Strings.Trim(txtDESInput.Text)) != 0 && Strings.Len(Strings.Trim(txtDESKey.Text)) != 0 && Strings.Len(Strings.Trim(cbDESMode.Text)) != 0)
            {
                //Calculator time execution....
                Stopwatch sw = Stopwatch.StartNew();
                sw.Start();

                enabledOrDisableDESButtons(false);

                string inputFileName, mode, keySize, key;
                string outputFileName = this.txtDESOutput.Text;
                key = txtDESKey.Text;
                if (key.Length < 8)
                {
                    MessageBox.Show("Độ dài KEY phải lớn hơn hoặc bằng 8!");
                    enabledOrDisableDESButtons(true);
                    return;
                }

                inputFileName = txtDESInput.Text;

                mode = cbDESMode.Text;

                if (key.Length >= 8 && key.Length < 12)
                    for (int i = 0; i < 12 - txtDESKey.Text.Length; i++)
                        key += "t";

                if (key.Length >= 12) key = key.Substring(0, 11) + "=";

                if (this.rbDESInputFile.Checked) // Encrypt 1 file.
                    DESAlgorithm(inputFileName, outputFileName, key, mode, false);
                else
                {
                    //Get all files ".encrypted" from path.
                    string[] filePaths = Directory.GetFiles(inputFileName, "*.*");

                    filePaths = Directory.GetFiles(inputFileName, "*.*", SearchOption.AllDirectories);

                    if (filePaths.Length == 0)
                    {
                        MessageBox.Show("Thư mục hiện tại không có chứa file !");
                        enabledOrDisableDESButtons(true);
                        return;
                    }

                    for (int i = 0; i < filePaths.Length; i++)
                    {
                        if (Path.GetFileName(filePaths[i]) != "Thumbs.db")
                        {
                            string outputFile = filePaths[i].Replace(this.txtDESInput.Text, this.txtDESOutput.Text);
                            string outputDir = Path.GetDirectoryName(outputFile);
                            if (!Directory.Exists(outputDir))
                                Directory.CreateDirectory(outputDir);
                            DESAlgorithm(filePaths[i], outputFile, key, mode, false);
                        }
                    }
                }
                enabledOrDisableDESButtons(true);
                sw.Stop();
                double elapsedMs = sw.Elapsed.TotalMilliseconds / 1000;
                MessageBox.Show("Tổng thời gian chương trình đã thực thi là : " + elapsedMs.ToString() + " s");
            }
            else
            {
                MessageBox.Show("Dữ liệu không đủ để chương trình gải mã ! Vui lòng cung cấp đầy đủ dữ liệu !");

            }
        }

        private void enabledOrDisableDESButtons(bool isEnable)
        {
            //this.cbAESMode.SelectionStart
            this.btnDESReset.Enabled = isEnable;
            //this.tbOutput.Enabled = isEnable;
            this.btnDESEncrypt.Enabled = isEnable;
            this.btnDESGenKey.Enabled = isEnable;
        }

        private void btnDESGenKey_Click(object sender, EventArgs e)
        {
            DESCryptoServiceProvider desCrypto = (DESCryptoServiceProvider)DESCryptoServiceProvider.Create();
            txtDESKey.Text = Convert.ToBase64String(desCrypto.Key);
        }

        private void btnDESInput_Click(object sender, EventArgs e)
        {
            if (rbDESInputFile.Checked)
            {
                OpenFileDialog ofd = new OpenFileDialog();
                ofd.Filter = "All Files (*.*)|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    this.txtDESInput.Text = ofd.FileName;
                    rbDESEncrypt_CheckedChanged(null, null);
                    rbDESDecrypt_CheckedChanged(null, null);
                }
            }
            else
            {
                FolderBrowserDialog fbd = new FolderBrowserDialog();
                if (fbd.ShowDialog() == DialogResult.OK)
                {
                    this.txtDESInput.Text = fbd.SelectedPath;
                    rbDESEncrypt_CheckedChanged(null, null);
                    rbDESDecrypt_CheckedChanged(null, null);
                }
            }
        }

        private void btnDESOutput_Click(object sender, EventArgs e)
        {
            
        }

        private void btnDESEncrypt_Click(object sender, EventArgs e)
        {
            if (rbDESEncrypt.Checked)
            {

                BtnEncryptDecryptDelegate s = new BtnEncryptDecryptDelegate(btnDESEncryptClick);
                s.BeginInvoke(null, null);
            }
            else
            {
                BtnEncryptDecryptDelegate s = new BtnEncryptDecryptDelegate(btnDESDecryptClick);
                s.BeginInvoke(null, null);
            }
        }

        private void btnDESReset_Click(object sender, EventArgs e)
        {
            this.txtDESKey.Clear();
            this.txtDESInput.Clear();
            this.txtDESOutput.Clear();
            this.cbDESMode.Text = "CBC";
            this.lblDESProg.Text = "";
            this.lblDESProg.Update();
            this.lblDESProgPercent.Text = "0%";
            this.lblDESProgPercent.Update();
            if (this.pgbDES.Value > 0)
                this.pgbDES.Value = 0;
        }

        private void cbDESMode_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void rbDESEncrypt_CheckedChanged(object sender, EventArgs e)
        {
            if (this.rbDESEncrypt.Checked)
            {
                this.btnDESEncrypt.Text = "Encrypt";
                if (this.rbDESInputFile.Checked)
                {
                    if (!String.IsNullOrEmpty(this.txtDESInput.Text))
                    {
                        string ext = Path.GetExtension(this.txtDESInput.Text);
                        this.txtDESOutput.Text = this.txtDESInput.Text.Insert(this.txtDESInput.Text.Length - ext.Length, "_encrypted");
                    }
                }
                else
                {
                    if (!String.IsNullOrEmpty(this.txtDESInput.Text))
                        this.txtDESOutput.Text = this.txtDESInput.Text + "_encrypted";
                }
            }

        }

        private void rbDESDecrypt_CheckedChanged(object sender, EventArgs e)
        {
            if (this.rbDESDecrypt.Checked)
            {
                this.btnDESEncrypt.Text = "Decrypt";
                if (this.rbDESInputFile.Checked)
                {
                    if (!String.IsNullOrEmpty(this.txtDESInput.Text))
                    {
                        string fileName = Path.GetFileNameWithoutExtension(this.txtDESInput.Text);
                        if (fileName.Contains("_encrypted"))
                        {
                            this.txtDESOutput.Text = Path.GetDirectoryName(this.txtDESInput.Text) + "\\"
                           + fileName.Replace("_encrypted", "")
                           + Path.GetExtension(this.txtDESInput.Text);
                        }
                        else
                        {
                            this.txtDESOutput.Text = Path.GetDirectoryName(this.txtDESInput.Text) + "\\"
                           + fileName.Insert(fileName.Length, "_decrypted")
                           + Path.GetExtension(this.txtDESInput.Text);
                        }

                    }
                }
                else
                {
                    string[] dirs = this.txtDESInput.Text.Split('\\');
                    if (dirs.Last().Contains("_encrypted"))
                    {
                        this.txtDESOutput.Text = Path.GetDirectoryName(this.txtDESInput.Text) + "\\" + dirs.Last().Replace("_encrypted", "");
                    }
                    else
                    {
                        this.txtDESOutput.Text = this.txtDESInput.Text + "_decrypted";
                    }
                }
            }
        }

        #endregion

        #region RSA
        
        private void RSA_Algorithm(string inputFile, string outputFile, RSAParameters RSAKeyInfo, bool isEncrypt)
        {
            try
            {

                FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
                FileStream fsCiperText = new FileStream(outputFile, FileMode.Create, FileAccess.Write);
                fsCiperText.SetLength(0);

                byte[] bin, encryptedData;
                long rdlen = 0;
                long totlen = fsInput.Length;
                int len;
                this.pgbRSA.Minimum = 0;
                this.pgbRSA.Maximum = 100;

                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSA.ImportParameters(RSAKeyInfo);

                int maxBytesCanEncrypted;
                if (isEncrypt)
                    maxBytesCanEncrypted = ((RSA.KeySize - 384) / 8) + 37;
                else
                    maxBytesCanEncrypted = RSA.KeySize / 8;

                //Read from the input file, then encrypt and write to the output file.
                while (rdlen < totlen)
                {
                    bin = new byte[maxBytesCanEncrypted];
                    len = fsInput.Read(bin, 0, maxBytesCanEncrypted);

                    if (isEncrypt) encryptedData = RSA.Encrypt(bin, false);
                    else encryptedData = RSA.Decrypt(bin, false);

                    fsCiperText.Write(encryptedData, 0, encryptedData.Length);
                    rdlen = rdlen + len;

                    this.lblRSAProg.Text = "Tên tệp xử lý : " + Path.GetFileName(inputFile);
                    this.lblRSAProg.Refresh();
                    this.lblRSAProgPercent.Text = ((long)(rdlen * 100) / totlen).ToString() + " %";
                    this.lblRSAProgPercent.Refresh();

                    this.pgbRSA.Value = (int)((rdlen * 100) / totlen);
                }

                fsCiperText.Close();
                fsInput.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed: " + ex.Message);
            }
        }

        private void btnRSAEncryptClick()
        {
            if (InvokeRequired)
            {
                this.Invoke(new MethodInvoker(btnRSAEncryptClick));
                return;
            }

            enabledOrDisableRSAButtons(false);

            if (this.txtRSAPriKeyFile.Text.Length == 0 || this.txtRSAN.Text.Length == 0 || this.txtRSAD.Text.Length == 0 || this.txtRSAE.Text.Length == 0)
            {
                MessageBox.Show("Key không hợp lệ ! Vui lòng chọn lại tệp tin key hoặc nhấn generate để tự sinh ! Xin cảm ơn! ");
                enabledOrDisableRSAButtons(true);
                return;
            }

            try
            {
                if (Strings.Len(Strings.Trim(txtRSAInput.Text)) != 0 &&
                Strings.Len(Strings.Trim(txtRSAPriKeyFile.Text)) != 0 &&
                Strings.Len(Strings.Trim(txtRSAN.Text)) != 0)
                {

                    Stopwatch sw = Stopwatch.StartNew();
                    sw.Start();

                    string inputFileName = txtRSAInput.Text;
                    string outputFileName = this.txtRSAOutput.Text;

                    //get Keys.
                    RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                    RSA.FromXmlString(File.ReadAllText(this.txtRSAPriKeyFile.Text));
                    if (this.rbRSAInputFile.Checked)
                        RSA_Algorithm(inputFileName, outputFileName, RSA.ExportParameters(true), true);
                    else
                    {
                        string[] filePaths = Directory.GetFiles(inputFileName, "*", SearchOption.AllDirectories);

                        if (filePaths.Length == 0 || (filePaths.Length == 1 && (Path.GetFileName(filePaths[0]) == "Thumbs.db")))
                        {
                            MessageBox.Show("Thư mục rỗng!");
                            enabledOrDisableRSAButtons(true);
                            return;
                        }

                        for (int i = 0; i < filePaths.Length; i++)
                        {
                            if (Path.GetFileName(filePaths[i]) != "Thumbs.db")
                            {
                                string outputFile = filePaths[i].Replace(this.txtRSAInput.Text, this.txtRSAOutput.Text);
                                string outputDir = Path.GetDirectoryName(outputFile);
                                if (!Directory.Exists(outputDir))
                                    Directory.CreateDirectory(outputDir);
                                RSA_Algorithm(filePaths[i], outputFile, RSA.ExportParameters(true), true);
                            }
                        }

                    }
                    enabledOrDisableRSAButtons(true);
                    sw.Stop();
                    double elapsedMs = sw.Elapsed.TotalMilliseconds / 1000;
                    MessageBox.Show("Thời gian thực thi " + elapsedMs.ToString() + "s");
                }
                else
                {
                    enabledOrDisableRSAButtons(true);
                    MessageBox.Show("Dữ liệu không đủ để mã hóa!");
                }
            }
            catch (Exception ex)
            {
                enabledOrDisableRSAButtons(true);
                MessageBox.Show("Failed: " + ex.Message);
            }
            enabledOrDisableRSAButtons(true);
        }

        private void btnRSADecryptClick()
        {
            if (InvokeRequired)
            {
                this.Invoke(new MethodInvoker(btnRSADecryptClick));
                return;
            }

            enabledOrDisableRSAButtons(false);

            try
            {
                if (Strings.Len(Strings.Trim(txtRSAInput.Text)) != 0 &&
                   Strings.Len(Strings.Trim(this.txtRSAPriKeyFile.Text)) != 0 &&
                   Strings.Len(Strings.Trim(this.txtRSAN.Text)) != 0)
                {
                    //Calculator time ex...
                    Stopwatch sw = Stopwatch.StartNew();
                    sw.Start();

                    string inputFileName = txtRSAInput.Text;
                    string outputFileName = txtRSAOutput.Text;
                    
                    RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                    RSA.FromXmlString(File.ReadAllText(this.txtRSAPriKeyFile.Text));

                    if (this.rbRSAInputFile.Checked)
                    {
                        RSA_Algorithm(inputFileName, outputFileName, RSA.ExportParameters(true), false);
                    }
                    else
                    {
                        string[] filePaths = Directory.GetFiles(inputFileName, "*.*", SearchOption.AllDirectories);
                        if (filePaths.Length == 0 || (filePaths.Length == 1 && (Path.GetFileName(filePaths[0]) == "Thumbs.db")))
                        {
                            MessageBox.Show("Thư mục rỗng!");
                            enabledOrDisableRSAButtons(true);
                            return;
                        }

                        for (int i = 0; i < filePaths.Length; i++)
                        {
                            if (Path.GetFileName(filePaths[i]) != "Thumbs.db")
                            {
                                string outputFile = filePaths[i].Replace(this.txtRSAInput.Text, this.txtRSAOutput.Text);
                                string outputDir = Path.GetDirectoryName(outputFile);
                                if (!Directory.Exists(outputDir))
                                    Directory.CreateDirectory(outputDir);
                                RSA_Algorithm(filePaths[i], outputFile, RSA.ExportParameters(true), false);
                            }
                        }
                    }
                    enabledOrDisableRSAButtons(true);
                    sw.Stop();
                    double elapsedMs = sw.Elapsed.TotalMilliseconds / 1000;
                    MessageBox.Show("Thời gian thực thi " + elapsedMs.ToString() + "s");
                }
                else
                {
                    MessageBox.Show("Không đủ điều kiện để giải mã !");
                }

            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed: " + ex.Message);
            }
            enabledOrDisableRSAButtons(true);
        }

        private void enabledOrDisableRSAButtons(bool isEnable)
        {

            this.btnRSAReset.Enabled = isEnable;
            this.btnRSAEncrypt.Enabled = isEnable;
            this.btnRSAGenKey.Enabled = isEnable;
        }

        private void btnRSAInputKey_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Filter = ".xml File (*.xml)|*.xml";
            ofd.FileName = "";
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                this.txtHashInput.Text = ofd.FileName;
            }

            if (File.Exists(ofd.FileName))
            {

                if (Path.GetExtension(ofd.FileName) == ".xml")
                {
                    XmlDocument xml = new XmlDocument();
                    xml.LoadXml(File.ReadAllText(ofd.FileName));
                    try
                    {
                        XmlNode xnList = xml.SelectSingleNode("/RSAKeyValue/Modulus");
                        txtRSAN.Text = xnList.InnerText;
                        xnList = xml.SelectSingleNode("/RSAKeyValue/Exponent");
                        txtRSAE.Text = xnList.InnerText;
                        xnList = xml.SelectSingleNode("/RSAKeyValue/D");
                        txtRSAD.Text = xnList.InnerText;
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Failed: " + ex.Message);
                    }
                }
            }
        }

        private void btnRSAGenKey_Click(object sender, EventArgs e)
        {
            try
            {

                int lengthKey = 0;
                if (this.cbRSAKeyLength.Text == "1024bits") lengthKey = 1024;
                else if (this.cbRSAKeyLength.Text == "512bits") lengthKey = 512;
                else if (this.cbRSAKeyLength.Text == "2048bits") lengthKey = 2048;
                else if (this.cbRSAKeyLength.Text == "4096bits") lengthKey = 4096;

                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(lengthKey);

                //String pathPrivateKey = @"D:\privateKey.xml";
                String pathPrivateKey = Path.Combine(System.IO.Path.GetDirectoryName(Application.ExecutablePath), "keys.xml");

                File.WriteAllText(pathPrivateKey, RSA.ToXmlString(true));  // Private Key

                txtRSAPriKeyFile.Text = pathPrivateKey;

                if (File.Exists(pathPrivateKey))
                {
                    if (Path.GetExtension(pathPrivateKey) == ".xml")
                    {
                        XmlDocument xml = new XmlDocument();
                        xml.LoadXml(File.ReadAllText(pathPrivateKey));
                        try
                        {
                            XmlNode xnList = xml.SelectSingleNode("/RSAKeyValue/Modulus");
                            txtRSAN.Text = xnList.InnerText;
                            xnList = xml.SelectSingleNode("/RSAKeyValue/Exponent");
                            txtRSAE.Text = xnList.InnerText;
                            xnList = xml.SelectSingleNode("/RSAKeyValue/D");
                            txtRSAD.Text = xnList.InnerText;
                        }
                        catch (Exception ix)
                        {
                            MessageBox.Show(ix.Message);
                        }
                    }
                }
                MessageBox.Show("Tạo khóa thành công với độ dài " + lengthKey.ToString() + " bits. Đường dẫn: " + pathPrivateKey);
            }
            catch (Exception ie)
            {
                MessageBox.Show("Failed: " + ie.Message);
            }

        }

        private void btnRSAOutput_Click(object sender, EventArgs e)
        {
            if (Strings.Len(Strings.Trim(txtRSAOutput.Text)) > 0)
            {
                try
                {
                    System.Diagnostics.Process prc = new System.Diagnostics.Process();
                    prc.StartInfo.FileName = Path.GetDirectoryName(txtRSAOutput.Text);
                    prc.Start();
                }
                catch (Exception ioex)
                {
                    MessageBox.Show("Failed: " + ioex.Message);
                }
            }
            else
            {
                MessageBox.Show("Không mở được,do quá trình mã hóa\nhoặc giải mã chưa thực thi!");
            }
        }

        private void btnRSAInputPath_Click(object sender, EventArgs e)
        {
            if (this.rbRSAInputFile.Checked)
            {
                OpenFileDialog ofd = new OpenFileDialog();
                ofd.Filter = "All Files (*.*)|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    this.txtRSAInput.Text = ofd.FileName;
                    rbRSAEncrypt_CheckedChanged(null, null);
                    rbRSADecrypt_CheckedChanged(null, null);
                }
            }
            else
            {
                FolderBrowserDialog fbd = new FolderBrowserDialog();
                if (fbd.ShowDialog() == DialogResult.OK)
                {
                    this.txtRSAInput.Text = fbd.SelectedPath;
                    rbRSAEncrypt_CheckedChanged(null, null);
                    rbRSADecrypt_CheckedChanged(null, null);
                }
            }
        }
        
        private void rbRSAEncrypt_CheckedChanged(object sender, EventArgs e)
        {
            if (this.rbRSAEncrypt.Checked)
            {
                this.btnRSAEncrypt.Text = "Encrypt";
                if (this.rbRSAInputFile.Checked)
                {
                    if (!String.IsNullOrEmpty(this.txtRSAInput.Text))
                    {
                        string ext = Path.GetExtension(this.txtRSAInput.Text);
                        this.txtRSAOutput.Text = this.txtRSAInput.Text.Insert(this.txtRSAInput.Text.Length - ext.Length, "_encrypted");
                    }
                }
                else
                {
                    if (!String.IsNullOrEmpty(this.txtRSAInput.Text))
                        this.txtRSAOutput.Text = this.txtRSAInput.Text + "_encrypted";
                }
            }
        }
        
        private void rbRSADecrypt_CheckedChanged(object sender, EventArgs e)
        {
            if (this.rbRSADecrypt.Checked)
            {
                this.btnRSAEncrypt.Text = "Decrypt";
                if (this.rbRSAInputFile.Checked)
                {
                    if (!String.IsNullOrEmpty(this.txtRSAInput.Text))
                    {
                        string fileName = Path.GetFileNameWithoutExtension(this.txtRSAInput.Text);
                        if (fileName.Contains("_encrypted"))
                        {
                            this.txtRSAOutput.Text = Path.GetDirectoryName(this.txtRSAInput.Text) + "\\"
                           + fileName.Replace("_encrypted", "")
                           + Path.GetExtension(this.txtRSAInput.Text);
                        }
                        else
                        {
                            this.txtRSAOutput.Text = Path.GetDirectoryName(this.txtRSAInput.Text) + "\\"
                           + fileName.Insert(fileName.Length, "_decrypted")
                           + Path.GetExtension(this.txtRSAInput.Text);
                        }
                    }
                }
                else
                {
                    string[] dirs = this.txtRSAInput.Text.Split('\\');
                    if (dirs.Last().Contains("_encrypted"))
                    {
                        this.txtRSAOutput.Text = Path.GetDirectoryName(this.txtRSAInput.Text) + "\\" + dirs.Last().Replace("_encrypted", "");
                    }
                    else
                    {
                        this.txtRSAOutput.Text = this.txtRSAInput.Text + "_decrypted";
                    }

                }
            }
        }
        
        private void btnRSAEncrypt_Click(object sender, EventArgs e)
        {
            if (rbRSAEncrypt.Checked)
            {
                BtnEncryptDecryptDelegate s = new BtnEncryptDecryptDelegate(btnRSAEncryptClick);
                s.BeginInvoke(null, null);
            }
            else
            {
                BtnEncryptDecryptDelegate s = new BtnEncryptDecryptDelegate(btnRSADecryptClick);
                s.BeginInvoke(null, null);
            }
        }
        
        private void btnRSAReset_Click(object sender, EventArgs e)
        {
            txtRSAPriKeyFile.Clear();
            cbRSAKeyLength.SelectedIndex = 0;
            rbRSAEncrypt.Checked = true;
            rbRSADecrypt.Checked = false;
            txtRSAN.Clear();
            txtRSAE.Clear();
            txtRSAD.Clear();
            txtRSAInput.Clear();
            txtRSAOutput.Clear();
            lblRSAProg.Text = "";
            lblRSAProg.Update();
            lblRSAProg.Refresh();
            lblRSAProgPercent.Text = "";
            lblRSAProgPercent.Update();
            lblRSAProgPercent.Refresh();
            pgbRSA.Value = 0;
        }

        #endregion

        #region Hash

        private void cbHFileOrText_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (cbHFileOrText.SelectedIndex == 1)
            {
                this.btnHashInput.Enabled = false;
            }
            else
            {
                this.btnHashInput.Enabled = true;
            }
        }

        private void btnHashInput_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Filter = "All Files (*.*)|*.*";
            ofd.FileName = "";
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                this.txtHashInput.Text = ofd.FileName;
            }
        }
        
        private void btnHashCalculateClick()
        {

            if (InvokeRequired)
            {
                this.Invoke(new MethodInvoker(btnHashCalculateClick));
                return;
            }

            if (this.ckbHashCompare.Checked && this.txtHashCompare.Text.Length == 0)
            {
                MessageBox.Show("Vui lòng nhập mã cần được điểm tra!"); return;
            }

            if (this.txtHashInput.Text.Length == 0)
            { MessageBox.Show("Vui lòng nhập dữ liệu là file hoặc text!"); return; }

            try
            {
                String ext = Path.GetExtension(this.txtHashInput.Text);

                if (this.cbHFileOrText.Text == "File")
                {
                    if (ext.Length == 0) { MessageBox.Show("Đây không phải là file!"); return; }

                    if (!File.Exists(this.txtHashInput.Text)) throw new FileNotFoundException("File : " + this.txtHashInput.Text + " không tồn tại!");

                    if (this.cbHashAlg.Text == "MD5")
                        txtHashResult.Text = HashFile(this.txtHashInput.Text, new MD5CryptoServiceProvider());
                    else if (this.cbHashAlg.Text == "SHA1")
                        txtHashResult.Text = HashFile(this.txtHashInput.Text, new SHA1Managed());
                    else if (this.cbHashAlg.Text == "SHA256")
                        txtHashResult.Text = HashFile(this.txtHashInput.Text, new SHA256Managed());
                    else if (this.cbHashAlg.Text == "SHA384")
                        txtHashResult.Text = HashFile(this.txtHashInput.Text, new SHA384Managed());
                    else if (this.cbHashAlg.Text == "SHA512")
                        txtHashResult.Text = HashFile(this.txtHashInput.Text, new SHA512Managed());
                    else if (this.cbHashAlg.Text == "RIPEMD160")
                        txtHashResult.Text = HashFile(this.txtHashInput.Text, new RIPEMD160Managed());
                    else
                    {
                        MessageBox.Show("Thuật toán Hash không hợp lệ!"); return;
                    }


                }
                else if (this.cbHFileOrText.Text == "Text")
                {
                    var inputBytes = System.Text.Encoding.ASCII.GetBytes(txtHashInput.Text);
                    byte[] hashBytes;

                    if (this.cbHashAlg.Text == "MD5")
                        hashBytes = new MD5CryptoServiceProvider().ComputeHash(inputBytes);
                    else if (this.cbHashAlg.Text == "SHA1")
                        hashBytes = new SHA1Managed().ComputeHash(inputBytes);
                    else if (this.cbHashAlg.Text == "SHA256")
                        hashBytes = new SHA256Managed().ComputeHash(inputBytes);
                    else if (this.cbHashAlg.Text == "SHA384")
                        hashBytes = new SHA384Managed().ComputeHash(inputBytes);
                    else if (this.cbHashAlg.Text == "SHA512")
                        hashBytes = new SHA512Managed().ComputeHash(inputBytes);
                    else if (this.cbHashAlg.Text == "RIPEMD160")
                        hashBytes = new RIPEMD160Managed().ComputeHash(inputBytes);
                    else
                    {
                        MessageBox.Show("Thuật toán Hash không hợp lệ!"); return;
                    }

                    // Convert the byte array to hexadecimal string
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < hashBytes.Length; i++)
                    {
                        sb.Append(hashBytes[i].ToString("X2"));
                    }
                    txtHashResult.Text = sb.ToString();
                }

                if (ckbHashCompare.Checked)
                {
                    if (this.txtHashResult.Text == this.txtHashCompare.Text.ToUpper())
                        MessageBox.Show("Khớp mã!");
                    else MessageBox.Show("Mã không khớp!");
                    
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed : " + ex.Message);
            }
        }

        public static string HashFile(string fileName, HashAlgorithm algorithm)
        {
            using (var stream = File.OpenRead(fileName))
            {
                return BitConverter.ToString(algorithm.ComputeHash(stream)).Replace("-", "").ToUpper();
            }
        }
        
        private void btnHashCalculate_Click(object sender, EventArgs e)
        {
            BtnEncryptDecryptDelegate s = new BtnEncryptDecryptDelegate(btnHashCalculateClick);
            s.BeginInvoke(null, null);
        }

        #endregion

    }
}
