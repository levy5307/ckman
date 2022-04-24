package common

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/housepower/ckman/config"
	"github.com/housepower/ckman/log"

	"github.com/pkg/errors"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func sshConnectwithPassword(user, password string) (*ssh.ClientConfig, error) {
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		Timeout:         30 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}

func sshConnectwithPublickKey(user string) (*ssh.ClientConfig, error) {
	key, err := os.ReadFile(path.Join(config.GetWorkDirectory(), "conf", "id_rsa"))
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		Timeout:         30 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}

func SSHConnect(user, password, host string, port int) (*ssh.Client, error) {
	var (
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		err          error
	)

	if password == "" {
		clientConfig, err = sshConnectwithPublickKey(user)
	} else {
		clientConfig, err = sshConnectwithPassword(user, password)
	}
	if err != nil {
		return nil, err
	}

	// connet to ssh
	addr = fmt.Sprintf("%s:%d", host, port)

	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		err = errors.Wrapf(err, "")
		return nil, err
	}

	return client, nil
}

func SFTPConnect(user, password, host string, port int) (*sftp.Client, error) {
	var (
		addr         string
		clientConfig *ssh.ClientConfig
		sshClient    *ssh.Client
		sftpClient   *sftp.Client
		err          error
	)

	if password == "" {
		clientConfig, err = sshConnectwithPublickKey(user)
	} else {
		clientConfig, err = sshConnectwithPassword(user, password)
	}
	if err != nil {
		return nil, err
	}

	// connet to ssh
	addr = fmt.Sprintf("%s:%d", host, port)

	if sshClient, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		err = errors.Wrapf(err, "")
		return nil, err
	}

	// create sftp client
	if sftpClient, err = sftp.NewClient(sshClient); err != nil {
		err = errors.Wrapf(err, "")
		return nil, err
	}

	return sftpClient, nil
}

func SFTPUpload(sftpClient *sftp.Client, localFilePath, remoteFilePath string) error {
	srcFile, err := os.Open(localFilePath)
	if err != nil {
		err = errors.Wrapf(err, "")
		return err
	}
	defer srcFile.Close()

	dstFile, err := sftpClient.Create(remoteFilePath)
	if err != nil {
		err = errors.Wrapf(err, "")
		return err
	}
	defer dstFile.Close()

	buf := make([]byte, 1024*1024)
	for {
		n, _ := srcFile.Read(buf)
		if n == 0 {
			break
		}
		_, _ = dstFile.Write(buf[0:n])
	}

	return nil
}

func SFTPDownload(sftpClient *sftp.Client, remoteFilePath, localFilePath string) error {
	dstFile, err := os.Create(localFilePath)
	if err != nil {
		err = errors.Wrapf(err, "")
		return err
	}
	defer dstFile.Close()

	srcFile, err := sftpClient.Open(remoteFilePath)
	if err != nil {
		err = errors.Wrapf(err, "")
		return err
	}
	defer srcFile.Close()

	buf := make([]byte, 1024*1024)
	for {
		n, _ := srcFile.Read(buf)
		if n == 0 {
			break
		}
		_, _ = dstFile.Write(buf[0:n])
	}

	return nil
}

func SSHRun(client *ssh.Client, password, shell string) (result string, err error) {
	var session *ssh.Session
	var buf []byte
	// create session
	if session, err = client.NewSession(); err != nil {
		err = errors.Wrapf(err, "")
		return
	}
	defer session.Close()

	log.Logger.Debugf("shell: %s", shell)

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	err = session.RequestPty("xterm", 80, 40, modes)
	if err != nil {
		return "", err
	}
	in, err := session.StdinPipe()
	if err != nil {
		return "", err
	}

	out, err := session.StdoutPipe()
	if err != nil {
		return "", err
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func(in io.WriteCloser, out io.Reader, output *[]byte) {
		defer wg.Done()
		var (
			line string
			r    = bufio.NewReader(out)
		)

		for {
			b, err := r.ReadByte()
			if err != nil {
				break
			}
			*output = append(*output, b)
			if b == byte('\n') {
				line = ""
				continue
			}
			line += string(b)
			// TODO I have no idea to slove this problem: "xxx is not in the sudoers file.  This incident will be reported."
			if strings.HasPrefix(line, "[sudo] password for ") && strings.HasSuffix(line, ": ") {
				_, err = in.Write([]byte(password + "\n"))
				if err != nil {
					break
				}
			}
		}
	}(in, out, &buf)

	_, err = session.Output(shell)
	if err != nil {
		return "", err
	}
	wg.Wait()
	result = strings.TrimRight(string(buf), "\n")
	result = strings.TrimRight(result, "\r")
	if strings.HasPrefix(result, "[sudo] password for ") {
		result = result[strings.Index(result, "\n")+1:]
	}
	result = result[strings.Index(result, "i love china")+12:]
	result = strings.TrimLeft(result, "\r")
	result = strings.TrimLeft(result, "\n")
	log.Logger.Debugf("output:%s", result)
	return
}

func ScpUploadFiles(files []string, remotePath, user, password, ip string, port int) error {
	sftpClient, err := SFTPConnect(user, password, ip, port)
	if err != nil {
		return err
	}
	defer sftpClient.Close()

	for _, file := range files {
		if file == "" {
			continue
		}
		remoteFile := path.Join(remotePath, path.Base(file))
		err = ScpUploadFile(file, remoteFile, user, password, ip, port)
		if err != nil {
			return err
		}
	}
	return nil
}

func ScpUploadFile(localFile, remoteFile, user, password, ip string, port int) error {
	sftpClient, err := SFTPConnect(user, password, ip, port)
	if err != nil {
		return err
	}
	defer sftpClient.Close()
	// delete remote file first, beacuse maybe the remote file exists and created by root
	cmd := fmt.Sprintf("rm -rf %s", remoteFile)
	if _, err = RemoteExecute(user, password, ip, port, cmd); err != nil {
		return err
	}

	if err = SFTPUpload(sftpClient, localFile, remoteFile); err != nil {
		return err
	}

	return nil
}

func ScpDownloadFiles(files []string, localPath, user, password, ip string, port int) error {
	sftpClient, err := SFTPConnect(user, password, ip, port)
	if err != nil {
		return err
	}
	defer sftpClient.Close()

	for _, file := range files {
		baseName := path.Base(file)
		err = SFTPDownload(sftpClient, file, path.Join(localPath, baseName))
		if err != nil {
			return err
		}
	}
	return nil
}

func ScpDownloadFile(remoteFile, localFile, user, password, ip string, port int) error {
	sftpClient, err := SFTPConnect(user, password, ip, port)
	if err != nil {
		return err
	}
	defer sftpClient.Close()

	err = SFTPDownload(sftpClient, remoteFile, localFile)
	if err != nil {
		return err
	}
	return nil
}

func RemoteExecute(user, password, host string, port int, cmd string) (string, error) {
	client, err := SSHConnect(user, password, host, port)
	if err != nil {
		return "", err
	}
	defer client.Close()

	finalScript := genFinalScript(cmd)
	var output string
	if output, err = SSHRun(client, password, finalScript); err != nil {
		log.Logger.Errorf("run '%s' on host %s fail: %s", cmd, host, output)
		return "", err
	}
	return output, nil
}

func genFinalScript(cmd string) string {
	return fmt.Sprintf("echo 'i love china'; %s", cmd)
}
