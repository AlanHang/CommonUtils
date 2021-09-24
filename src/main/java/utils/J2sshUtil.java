package utils;

import com.sshtools.net.SocketTransport;
import com.sshtools.publickey.SshPrivateKeyFile;
import com.sshtools.publickey.SshPrivateKeyFileFactory;
import com.sshtools.scp.ScpClient;
import com.sshtools.ssh.PublicKeyAuthentication;
import com.sshtools.ssh.SshAuthentication;
import com.sshtools.ssh.SshConnector;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.SshKeyPair;
import com.sshtools.ssh2.Ssh2Client;
import com.sshtools.ssh2.Ssh2PasswordAuthentication;
import com.sshtools.ssh2.Ssh2Session;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

/**
 * @author ZhengHang
 * @create 2021-09-24 9:41
 */
public class J2sshUtil {
    /**
     * @param sshInfo ssh连接信息
     * @return {@link Ssh2Client } ssh的客户端
     * @throws Exception 异常信息
     */
    private static Ssh2Client getSsh2Client(SshInfo sshInfo) throws Exception {
        Ssh2Client ssh2Client;
        SshConnector con = SshConnector.createInstance();
        SocketTransport transport = new SocketTransport(sshInfo.getIp(), sshInfo.getPort());
        transport.setSoTimeout(60 * 60 * 1000);
        ssh2Client = con.connect(transport, sshInfo.getUserName());
        if (sshInfo.getKeyFile() == null || "".equals(sshInfo.getKeyFile())) {
            Ssh2PasswordAuthentication pwd = new Ssh2PasswordAuthentication();
            do {
                pwd.setPassword(sshInfo.getPassword());
            } while (ssh2Client.authenticate(pwd) != Ssh2PasswordAuthentication.COMPLETE && ssh2Client.isAuthenticated());
        } else {
            PublicKeyAuthentication keyGen = new PublicKeyAuthentication();
            do {
                SshPrivateKeyFile pkFile = SshPrivateKeyFileFactory.parse(new ByteArrayInputStream(sshInfo.getKeyFile().getBytes()));
                SshKeyPair pair;
                if (pkFile.isPassphraseProtected()) {
                    pair = pkFile.toKeyPair(sshInfo.getKeyWord());
                } else {
                    pair = pkFile.toKeyPair(null);
                }
                keyGen.setPrivateKey(pair.getPrivateKey());
                keyGen.setPublicKey(pair.getPublicKey());
                keyGen.setUsername(sshInfo.getUserName());
            } while (ssh2Client.authenticate(keyGen) != SshAuthentication.COMPLETE && ssh2Client.isConnected());
        }
        if (ssh2Client.isConnected()) {
            return ssh2Client;
        } else {
            return null;
        }
    }

    private static void closeSsh2Client(Ssh2Client ssh2Client) {
        if (ssh2Client != null && ssh2Client.isConnected()) {
            ssh2Client.disconnect();
        }
    }

    private static void closeSession(Ssh2Session session) {
        if (session != null && !session.isClosed()) {
            session.close();
        }
    }

    /**
     * ftp从远程下载文件
     *
     * @param sshInfo     ssh连接信息
     * @param remoteFiles 远程路径地址
     * @param localPath   本地文件夹路径
     * @return 获取文件是否成功
     * @throws Exception 异常信息
     */
    public static boolean getFiles(SshInfo sshInfo, String[] remoteFiles, String localPath) throws Exception {
        Ssh2Client ssh2Client = getSsh2Client(sshInfo);
        ScpClient scp = new ScpClient(ssh2Client);
        try {
            scp.get(localPath, remoteFiles, true);
        } finally {
            closeScp(scp);
            closeSsh2Client(ssh2Client);
        }
        return true;
    }

    private static void closeScp(ScpClient scpClient) throws IOException, SshException {
        if (scpClient != null) {
            scpClient.exit();
        }
    }

    /**
     * ssh在远程执行命令
     *
     * @param sshInfo  ssh连接信息
     * @param commands 执行的命令
     * @return 执行结果
     * @throws Exception 异常信息
     */
    public static ShellResult execShellCommands(SshInfo sshInfo, List<SshCommand> commands) throws Exception {
        Ssh2Client ssh2Client = getSsh2Client(sshInfo);
        Ssh2Session session = null;
        ShellResult shellResult = new ShellResult();
        int exitCode = 1;
        BufferedReader in = null;
        BufferedReader error = null;
        StringBuilder inResult = new StringBuilder();
        StringBuilder errorResult = new StringBuilder();
        try {
            if (ssh2Client != null && ssh2Client.isAuthenticated()) {
                StringBuilder allCommand = new StringBuilder(commands.size() * 50 + 16);
                for (SshCommand command : commands) {
                    allCommand.append(command);
                    allCommand.append(";");
                }
                if (allCommand.length() > 0) {
                    allCommand.deleteCharAt(allCommand.length() - 1);
                }
                session = (Ssh2Session) ssh2Client.openSessionChannel();
                session.executeCommand(allCommand.toString());
                in = new BufferedReader(new InputStreamReader(session.getInputStream(), "UTF-8"));
                error = new BufferedReader(new InputStreamReader(session.getStderrInputStream(), "UTF-8"));
                String line;
                while ((line = in.readLine()) != null) {
                    inResult.append(line).append("\r\n");
                }
                while ((line = error.readLine()) != null) {
                    errorResult.append(line).append("\r\n");
                }
            }
        } finally {
            if (error != null) {
                error.close();
            }
            if (in != null) {
                in.close();
            }
            closeSession(session);
            if (session != null) {
                exitCode = session.exitCode();
            }
            closeSsh2Client(ssh2Client);
        }
        shellResult.setExitCode(exitCode);
        shellResult.setOutput(inResult.toString());
        shellResult.setErrorMessage(errorResult.toString());
        return shellResult;
    }


    public static class SshInfo {
        /**
         * ssh连接的ip地址
         */
        private String ip;
        /**
         * ssh连接的端口，默认为22
         */
        private int port = 22;
        /**
         * ssh连接的用户名
         */
        private String userName;
        /**
         * ssh连接的密码
         */
        private String password;
        /**
         * ssh公钥连接的文件
         */
        private String keyFile;
        /**
         * ssh公钥连接的密码
         */
        private String keyWord;

        public SshInfo(String ip, int port, String userName, String password) {
            this.ip = ip;
            this.port = port;
            this.userName = userName;
            this.password = password;
        }

        public SshInfo(String ip, int port, String userName, String keyFile, String keyWord) {
            this.ip = ip;
            this.port = port;
            this.userName = userName;
            this.keyFile = keyFile;
            this.keyWord = keyWord;
        }

        public SshInfo() {
        }

        public String getIp() {
            return ip;
        }

        public void setIp(String ip) {
            this.ip = ip;
        }

        public int getPort() {
            return port;
        }

        public void setPort(int port) {
            this.port = port;
        }

        public String getUserName() {
            return userName;
        }

        public void setUserName(String userName) {
            this.userName = userName;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getKeyFile() {
            return keyFile;
        }

        public void setKeyFile(String keyFile) {
            this.keyFile = keyFile;
        }

        public String getKeyWord() {
            return keyWord;
        }

        public void setKeyWord(String keyWord) {
            this.keyWord = keyWord;
        }
    }

    public static class ShellResult {
        /**
         * 命令退出码
         */
        private int exitCode;
        /**
         * 命令错误信息
         */
        private String errorMessage;
        /**
         * 命令执行后的控制台输出
         */
        private String output;

        public ShellResult(int exitCode, String errorMessage, String output) {
            this.exitCode = exitCode;
            this.errorMessage = errorMessage;
            this.output = output;
        }

        public ShellResult() {
        }

        public int getExitCode() {
            return exitCode;
        }

        public void setExitCode(int exitCode) {
            this.exitCode = exitCode;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public void setErrorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
        }

        public String getOutput() {
            return output;
        }

        public void setOutput(String output) {
            this.output = output;
        }
    }

    public static class SshCommand {
        private String command;
        private long time = 1000L;

        public SshCommand(String command, long time) {
            this.command = command;
            this.time = time;
        }

        public SshCommand() {
        }

        public String getCommand() {
            return command;
        }

        public void setCommand(String command) {
            this.command = command;
        }

        public long getTime() {
            return time;
        }

        public void setTime(long time) {
            this.time = time;
        }

        @Override
        public String toString() {
            return "SshCommand{" +
                    "command='" + command + '\'' +
                    ", time=" + time +
                    '}';
        }
    }
}
