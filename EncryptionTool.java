import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

public class EncryptionTool extends JFrame {
    private JTextArea logArea;
    private JTextField filePathField;
    private JTextField outputPathField;
    private JComboBox<String> algorithmCombo;
    private JComboBox<String> modeCombo;
    private JTextField keyField;
    private JButton generateKeyButton;
    private JButton encryptButton;
    private JButton decryptButton;
    private JButton selectFileButton;
    private JButton selectOutputButton;
    private JProgressBar progressBar;
    
    private static final String[] ALGORITHMS = {"AES", "ChaCha20", "DES", "Blowfish"};
    private static final String[] MODES = {"GCM", "CBC", "ECB"};
    
    public EncryptionTool() {
        setTitle("XILLEN Encryption Tool v2.0");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(800, 600);
        setLocationRelativeTo(null);
        
        initComponents();
        setupLayout();
        setupEventHandlers();
    }
    
    private void initComponents() {
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logArea.setBackground(new Color(40, 40, 40));
        logArea.setForeground(new Color(0, 255, 0));
        
        filePathField = new JTextField();
        outputPathField = new JTextField();
        algorithmCombo = new JComboBox<>(ALGORITHMS);
        modeCombo = new JComboBox<>(MODES);
        keyField = new JTextField();
        
        generateKeyButton = new JButton("Generate Key");
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");
        selectFileButton = new JButton("Select File");
        selectOutputButton = new JButton("Select Output");
        
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        
        algorithmCombo.setSelectedItem("AES");
        modeCombo.setSelectedItem("GCM");
    }
    
    private void setupLayout() {
        setLayout(new BorderLayout());
        
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        JPanel inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        gbc.gridx = 0; gbc.gridy = 0;
        inputPanel.add(new JLabel("Input File:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        inputPanel.add(filePathField, gbc);
        gbc.gridx = 2; gbc.weightx = 0.0;
        inputPanel.add(selectFileButton, gbc);
        
        gbc.gridx = 0; gbc.gridy = 1;
        inputPanel.add(new JLabel("Output Path:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        inputPanel.add(outputPathField, gbc);
        gbc.gridx = 2; gbc.weightx = 0.0;
        inputPanel.add(selectOutputButton, gbc);
        
        gbc.gridx = 0; gbc.gridy = 2;
        inputPanel.add(new JLabel("Algorithm:"), gbc);
        gbc.gridx = 1; gbc.weightx = 0.0;
        inputPanel.add(algorithmCombo, gbc);
        
        gbc.gridx = 0; gbc.gridy = 3;
        inputPanel.add(new JLabel("Mode:"), gbc);
        gbc.gridx = 1; gbc.weightx = 0.0;
        inputPanel.add(modeCombo, gbc);
        
        gbc.gridx = 0; gbc.gridy = 4;
        inputPanel.add(new JLabel("Key:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        inputPanel.add(keyField, gbc);
        gbc.gridx = 2; gbc.weightx = 0.0;
        inputPanel.add(generateKeyButton, gbc);
        
        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);
        
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(inputPanel, BorderLayout.CENTER);
        topPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.add(new JLabel("Operation Log:"), BorderLayout.NORTH);
        centerPanel.add(new JScrollPane(logArea), BorderLayout.CENTER);
        centerPanel.add(progressBar, BorderLayout.SOUTH);
        
        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(centerPanel, BorderLayout.CENTER);
        
        add(mainPanel);
    }
    
    private void setupEventHandlers() {
        selectFileButton.addActionListener(e -> selectInputFile());
        selectOutputButton.addActionListener(e -> selectOutputFile());
        generateKeyButton.addActionListener(e -> generateKey());
        encryptButton.addActionListener(e -> encryptFile());
        decryptButton.addActionListener(e -> decryptFile());
        
        algorithmCombo.addActionListener(e -> updateModeOptions());
    }
    
    private void selectInputFile() {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            filePathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            updateOutputPath();
        }
    }
    
    private void selectOutputFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            outputPathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
        }
    }
    
    private void updateOutputPath() {
        String inputPath = filePathField.getText();
        if (!inputPath.isEmpty()) {
            File inputFile = new File(inputPath);
            String outputDir = outputPathField.getText();
            if (outputDir.isEmpty()) {
                outputDir = inputFile.getParent();
                outputPathField.setText(outputDir);
            }
        }
    }
    
    private void updateModeOptions() {
        String algorithm = (String) algorithmCombo.getSelectedItem();
        modeCombo.removeAllItems();
        
        if ("AES".equals(algorithm)) {
            modeCombo.addItem("GCM");
            modeCombo.addItem("CBC");
            modeCombo.addItem("ECB");
        } else if ("ChaCha20".equals(algorithm)) {
            modeCombo.addItem("ChaCha20-Poly1305");
        } else {
            modeCombo.addItem("CBC");
            modeCombo.addItem("ECB");
        }
        
        modeCombo.setSelectedIndex(0);
    }
    
    private void generateKey() {
        try {
            String algorithm = (String) algorithmCombo.getSelectedItem();
            String key = generateRandomKey(algorithm);
            keyField.setText(key);
            log("Generated new key for " + algorithm);
        } catch (Exception e) {
            log("Error generating key: " + e.getMessage());
        }
    }
    
    private String generateRandomKey(String algorithm) throws Exception {
        if ("AES".equals(algorithm)) {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey key = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(key.getEncoded());
        } else if ("ChaCha20".equals(algorithm)) {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            return Base64.getEncoder().encodeToString(key);
        } else {
            byte[] key = new byte[16];
            new SecureRandom().nextBytes(key);
            return Base64.getEncoder().encodeToString(key);
        }
    }
    
    private void encryptFile() {
        if (!validateInputs()) return;
        
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                encryptFileInternal();
                return null;
            }
        };
        worker.execute();
    }
    
    private void decryptFile() {
        if (!validateInputs()) return;
        
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                decryptFileInternal();
                return null;
            }
        };
        worker.execute();
    }
    
    private boolean validateInputs() {
        if (filePathField.getText().isEmpty()) {
            log("Please select input file");
            return false;
        }
        if (outputPathField.getText().isEmpty()) {
            log("Please select output directory");
            return false;
        }
        if (keyField.getText().isEmpty()) {
            log("Please enter or generate a key");
            return false;
        }
        return true;
    }
    
    private void encryptFileInternal() throws Exception {
        String inputPath = filePathField.getText();
        String outputPath = outputPathField.getText();
        String algorithm = (String) algorithmCombo.getSelectedItem();
        String mode = (String) modeCombo.getSelectedItem();
        String keyString = keyField.getText();
        
        log("Starting encryption...");
        log("Algorithm: " + algorithm + " " + mode);
        log("Input: " + inputPath);
        
        File inputFile = new File(inputPath);
        String outputFileName = inputFile.getName() + ".encrypted";
        File outputFile = new File(outputPath, outputFileName);
        
        byte[] inputData = Files.readAllBytes(inputFile.toPath());
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        
        byte[] encryptedData;
        if ("AES".equals(algorithm)) {
            encryptedData = encryptAES(inputData, keyBytes, mode);
        } else if ("ChaCha20".equals(algorithm)) {
            encryptedData = encryptChaCha20(inputData, keyBytes);
        } else {
            encryptedData = encryptGeneric(inputData, keyBytes, algorithm, mode);
        }
        
        Files.write(outputFile.toPath(), encryptedData);
        
        log("Encryption completed successfully");
        log("Output: " + outputFile.getAbsolutePath());
        log("Original size: " + inputData.length + " bytes");
        log("Encrypted size: " + encryptedData.length + " bytes");
    }
    
    private void decryptFileInternal() throws Exception {
        String inputPath = filePathField.getText();
        String outputPath = outputPathField.getText();
        String algorithm = (String) algorithmCombo.getSelectedItem();
        String mode = (String) modeCombo.getSelectedItem();
        String keyString = keyField.getText();
        
        log("Starting decryption...");
        log("Algorithm: " + algorithm + " " + mode);
        log("Input: " + inputPath);
        
        File inputFile = new File(inputPath);
        String outputFileName = inputFile.getName().replace(".encrypted", ".decrypted");
        File outputFile = new File(outputPath, outputFileName);
        
        byte[] inputData = Files.readAllBytes(inputFile.toPath());
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        
        byte[] decryptedData;
        if ("AES".equals(algorithm)) {
            decryptedData = decryptAES(inputData, keyBytes, mode);
        } else if ("ChaCha20".equals(algorithm)) {
            decryptedData = decryptChaCha20(inputData, keyBytes);
        } else {
            decryptedData = decryptGeneric(inputData, keyBytes, algorithm, mode);
        }
        
        Files.write(outputFile.toPath(), decryptedData);
        
        log("Decryption completed successfully");
        log("Output: " + outputFile.getAbsolutePath());
        log("Encrypted size: " + inputData.length + " bytes");
        log("Decrypted size: " + decryptedData.length + " bytes");
    }
    
    private byte[] encryptAES(byte[] data, byte[] key, String mode) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        
        if ("GCM".equals(mode)) {
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            
            byte[] encrypted = cipher.doFinal(data);
            byte[] result = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
            return result;
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        }
    }
    
    private byte[] decryptAES(byte[] data, byte[] key, String mode) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        
        if ("GCM".equals(mode)) {
            byte[] iv = new byte[12];
            byte[] encrypted = new byte[data.length - 12];
            System.arraycopy(data, 0, iv, 0, 12);
            System.arraycopy(data, 12, encrypted, 0, encrypted.length);
            
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            return cipher.doFinal(encrypted);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(data);
        }
    }
    
    private byte[] encryptChaCha20(byte[] data, byte[] key) throws Exception {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new GCMParameterSpec(128, nonce));
        
        byte[] encrypted = cipher.doFinal(data);
        byte[] result = new byte[nonce.length + encrypted.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(encrypted, 0, result, nonce.length, encrypted.length);
        return result;
    }
    
    private byte[] decryptChaCha20(byte[] data, byte[] key) throws Exception {
        byte[] nonce = new byte[12];
        byte[] encrypted = new byte[data.length - 12];
        System.arraycopy(data, 0, nonce, 0, 12);
        System.arraycopy(data, 12, encrypted, 0, encrypted.length);
        
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new GCMParameterSpec(128, nonce));
        return cipher.doFinal(encrypted);
    }
    
    private byte[] encryptGeneric(byte[] data, byte[] key, String algorithm, String mode) throws Exception {
        String transformation = algorithm + "/" + mode + "/PKCS5Padding";
        SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }
    
    private byte[] decryptGeneric(byte[] data, byte[] key, String algorithm, String mode) throws Exception {
        String transformation = algorithm + "/" + mode + "/PKCS5Padding";
        SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }
    
    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append("[" + java.time.LocalTime.now() + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
    
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeel());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        SwingUtilities.invokeLater(() -> {
            new EncryptionTool().setVisible(true);
        });
    }
}

