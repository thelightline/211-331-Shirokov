#include "mainwindow.h"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QFile>
#include <QTextStream>
#include <QCryptographicHash>
#include <QDebug>
#include <QDir>
#include <openssl/rand.h>
#include <QClipboard>
#include <QApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QGraphicsDropShadowEffect>
#include <QPropertyAnimation>
#include <QMessageBox>
#include <QInputDialog>
#ifdef Q_OS_WIN
#include <windows.h>
#endif

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    qDebug() << "Current working directory:" << QDir::currentPath();

    stackedWidget = new QStackedWidget(this);
    setCentralWidget(stackedWidget);

    setupLoginScreen();
    setupDataScreen();
    setupErrorScreen();

    stackedWidget->addWidget(loginScreen);
    stackedWidget->addWidget(dataScreen);
    stackedWidget->addWidget(errorScreen);

    connect(dataTable, &QTableWidget::cellDoubleClicked,
            this, &MainWindow::handleCellDoubleClick);
}

MainWindow::~MainWindow() {
    // Очищаем чувствительные данные
    for (auto& cred : memoryStorage) {
        cred.encryptedLogin.fill('*');
        cred.encryptedPassword.fill('*');
    }
    memoryStorage.clear();
}

void MainWindow::secureClear(QByteArray &data) {
    data.fill('*');
    data.clear();
}


QByteArray MainWindow::decryptData(const QByteArray &data, const QByteArray &key) {
    QByteArray decryptedData;
    if (!do_crypt(data, decryptedData, key, false)) {
        qDebug() << "Failed to decrypt data!";
        return QByteArray();
    }
    return decryptedData;
}


void MainWindow::setupLoginScreen() {
    loginScreen = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(loginScreen);

    QLabel *titleLabel = new QLabel("Enter Master PIN", this);
    titleLabel->setAlignment(Qt::AlignCenter);
    titleLabel->setStyleSheet("font-size: 16px; color: white; font-weight: bold;");

    QGraphicsDropShadowEffect *titleShadow = new QGraphicsDropShadowEffect(this);
    titleShadow->setBlurRadius(5);
    titleShadow->setColor(QColor(0, 0, 0, 160));
    titleShadow->setOffset(2, 2);
    titleLabel->setGraphicsEffect(titleShadow);

    // Добавляем QLabel для отображения ошибок
    errorLabel = new QLabel(this);
    errorLabel->setStyleSheet("color: #FF5555; font-size: 14px;");
    errorLabel->setAlignment(Qt::AlignCenter);
    errorLabel->hide();

    passwordField = new QLineEdit(this);
    passwordField->setPlaceholderText("Enter PIN");
    passwordField->setEchoMode(QLineEdit::Password);
    passwordField->setStyleSheet(
        "background-color: #404040; color: white; border: 1px solid #555;"
        "border-radius: 5px; padding: 8px;"
        "selection-background-color: #2A82DA;"
        );

    QPushButton *loginButton = new QPushButton("Login", this);
    loginButton->setStyleSheet(
        "QPushButton {"
        "   background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #505050, stop:1 #303030);"
        "   color: white; border: none; border-radius: 5px; padding: 10px;"
        "   font-size: 14px; font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "   background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #606060, stop:1 #404040);"
        "}"
        "QPushButton:pressed {"
        "   background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #404040, stop:1 #202020);"
        "}"
        );

    connect(loginButton, &QPushButton::clicked, this, &MainWindow::checkPassword);

    layout->addStretch(1);
    layout->addWidget(titleLabel);
    layout->addWidget(errorLabel);
    layout->addWidget(passwordField);
    layout->addWidget(loginButton);
    layout->addStretch(1);

    loginScreen->setLayout(layout);
}

void MainWindow::setupDataScreen() {
    dataScreen = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(dataScreen);

    QLabel *titleLabel = new QLabel("Credentials Storage", this);
    titleLabel->setAlignment(Qt::AlignCenter);
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; color: white;");

    QGraphicsDropShadowEffect *titleShadow = new QGraphicsDropShadowEffect(this);
    titleShadow->setBlurRadius(5);
    titleShadow->setColor(QColor(0, 0, 0, 160));
    titleShadow->setOffset(2, 2);
    titleLabel->setGraphicsEffect(titleShadow);

    // Поле фильтрации
    filterField = new QLineEdit(this);
    filterField->setPlaceholderText("Filter by site...");
    filterField->setStyleSheet(
        "background-color: #404040; color: white; border: 1px solid #555;"
        "border-radius: 5px; padding: 8px;"
        );
    connect(filterField, &QLineEdit::textChanged, this, &MainWindow::filterTable);

    // Таблица
    dataTable = new QTableWidget(this);
    dataTable->setColumnCount(3);
    dataTable->setHorizontalHeaderLabels({"Website", "Login", "Password"});
    dataTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    dataTable->setStyleSheet(
        "QTableWidget {"
        "   background-color: #303030; color: white; gridline-color: #555;"
        "   border: 1px solid #555; border-radius: 5px;"
        "}"
        "QHeaderView::section {"
        "   background-color: #404040; color: white; padding: 5px;"
        "   border: none;"
        "}"
        "QTableWidget::item {"
        "   padding: 5px;"
        "}"
        "QTableWidget::item:selected {"
        "   background-color: #2A82DA; color: white;"
        "}"
        );

    layout->addWidget(titleLabel);
    layout->addWidget(filterField);
    layout->addWidget(dataTable);

    dataScreen->setLayout(layout);
}

void MainWindow::filterTable(const QString &text) {
    for(int i = 0; i < dataTable->rowCount(); ++i) {
        QTableWidgetItem *siteItem = dataTable->item(i, 0);
        bool match = siteItem->text().contains(text, Qt::CaseInsensitive);
        dataTable->setRowHidden(i, !match);
    }
}

void MainWindow::setupErrorScreen() {
    errorScreen = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(errorScreen);

    errorLabelErrorScreen = new QLabel("Invalid PIN!", this);
    errorLabelErrorScreen->setStyleSheet("color: #FF5555; font-size: 18px; font-weight: bold;");
    errorLabelErrorScreen->setAlignment(Qt::AlignCenter);

    QGraphicsDropShadowEffect *shadowEffect = new QGraphicsDropShadowEffect(this);
    shadowEffect->setBlurRadius(5);
    shadowEffect->setColor(QColor(0, 0, 0, 160));
    shadowEffect->setOffset(2, 2);
    errorLabelErrorScreen->setGraphicsEffect(shadowEffect);

    QPushButton *backButton = new QPushButton("Back", this);
    backButton->setStyleSheet(
        "QPushButton {"
        "   background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #505050, stop:1 #303030);"
        "   color: white; border: none; border-radius: 5px; padding: 10px;"
        "   font-size: 14px; font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "   background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #606060, stop:1 #404040);"
        "}"
        "QPushButton:pressed {"
        "   background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #404040, stop:1 #202020);"
        "}"
        );
    connect(backButton, &QPushButton::clicked, this, &MainWindow::returnToLogin);

    layout->addWidget(errorLabelErrorScreen);
    layout->addWidget(backButton);
    errorScreen->setLayout(layout);
}

void MainWindow::checkPassword() {
    QString pin = passwordField->text();
    passwordField->clear();

    if (pin.isEmpty()) {
        errorLabel->setText("PIN cannot be empty!");
        errorLabel->show();
        return;
    } else {
        errorLabel->hide();
    }

    // Генерация ключа
    QByteArray key = QCryptographicHash::hash(
        pin.toUtf8(),
        QCryptographicHash::Sha3_256
        );
    qDebug() << "Generated key:" << key.toHex();

    QFile file("credentialsAES.json");
    if (!file.exists()) {
        qDebug() << "File not found. Creating new...";
        createEncryptedFile(key);
    }

    // Дешифровка
    if (decryptFile(key)) {
        loadDataToTable();
        stackedWidget->setCurrentWidget(dataScreen);
        errorLabel->hide();
    } else {
        errorLabel->setText("Invalid PIN or corrupted file!");
        errorLabel->show();
        stackedWidget->setCurrentWidget(errorScreen); // Альтернатива - переключение на errorScreen
    }

    key.fill(0);
}

void MainWindow::createEncryptedFile(const QByteArray &key) {
    QFile jsonFile("credentials.json");
    if (!jsonFile.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open credentials.json:" << jsonFile.errorString();
        errorLabelErrorScreen->setText("Default credentials file not found!");
        stackedWidget->setCurrentWidget(errorScreen);
        return;
    }

    QByteArray jsonData = jsonFile.readAll();
    jsonFile.close();

    // Шифруем в hex виде
    QByteArray encryptedData;
    if (!do_crypt(jsonData, encryptedData, key, true)) {
        qDebug() << "Encryption failed!";
        errorLabelErrorScreen->setText("Encryption Failed!");
        stackedWidget->setCurrentWidget(errorScreen);
        return;
    }

    QByteArray hexEncryptedData = encryptedData.toHex();

    QFile encFile("credentialsAES.json");
    if (!encFile.open(QIODevice::WriteOnly)) {
        qDebug() << "Failed to create enc file:" << encFile.errorString();
        errorLabelErrorScreen->setText("Failed to create encrypted file!");
        stackedWidget->setCurrentWidget(errorScreen);
        return;
    }

    encFile.write(hexEncryptedData);
    encFile.close();
    qDebug() << "New encrypted file created successfully";
}

bool MainWindow::decryptFile(const QByteArray &key) {
    QFile file("credentialsAES.json");
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open file:" << file.errorString();
        return false;
    }

    QByteArray hexEncryptedData = file.readAll();
    file.close();

    QByteArray encryptedData = QByteArray::fromHex(hexEncryptedData);

    QByteArray decryptedData;
    if (!do_crypt(encryptedData, decryptedData, key, false)) {
        qDebug() << "Decryption failed!";
        errorLabelErrorScreen->setText("Decryption failed!");
        stackedWidget->setCurrentWidget(errorScreen);
        decryptedData.fill(0);
        return false;
    }

    // Парсинг JSON
    QJsonDocument jsonDoc = QJsonDocument::fromJson(decryptedData);
    if (!jsonDoc.isObject()) {
        qDebug() << "Invalid JSON format";
        errorLabelErrorScreen->setText("Invalid JSON format in encrypted file!");
        stackedWidget->setCurrentWidget(errorScreen);
        return false;
    }

    QJsonObject jsonObj = jsonDoc.object();
    QJsonArray credentialsArray = jsonObj["credentials"].toArray();
    memoryStorage.clear();

    for (const QJsonValue &value : credentialsArray) {
        if (value.isObject()) {
            QJsonObject credential = value.toObject();
            if (credential.contains("hostname") && credential.contains("loginpassword")) {
                QString hostname = credential["hostname"].toString();
                QJsonObject loginpassword = credential["loginpassword"].toObject();

                if (loginpassword.contains("login") && loginpassword.contains("password")) {
                    QString login = loginpassword["login"].toString();
                    QString password = loginpassword["password"].toString();

                    // Шифруем логин и пароль вторым слоем
                    QByteArray encryptedLogin = encryptData(login.toUtf8(), key);
                    QByteArray encryptedPassword = encryptData(password.toUtf8(), key);

                    memoryStorage.append({hostname, encryptedLogin, encryptedPassword});
                } else {
                    qDebug() << "Missing login or password in loginpassword";
                }
            } else {
                qDebug() << "Missing hostname or loginpassword";
            }
        } else {
            qDebug() << "Value is not an object";
        }
    }

    decryptedData.fill(0); // Очищаем расшифрованные данные
    return true;
}

QByteArray MainWindow::encryptData(const QByteArray &data, const QByteArray &key) {
    QByteArray encryptedData;
    if (!do_crypt(data, encryptedData, key, true)) {
        qDebug() << "Failed to encrypt data!";
        return QByteArray();
    }
    return encryptedData;
}


bool MainWindow::do_crypt(const QByteArray &in, QByteArray &out, const QByteArray &key, bool encrypt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        qDebug() << "Failed to create EVP context";
        return false;
    }

    // Обработка IV
    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (encrypt) {
        if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
            qDebug() << "IV generation failed";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                                reinterpret_cast<const unsigned char*>(key.data()), iv)) {
            qDebug() << "EncryptInit failed";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    } else {
        if (in.size() < EVP_MAX_IV_LENGTH) {
            qDebug() << "Invalid encrypted data size";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        memcpy(iv, in.constData(), EVP_MAX_IV_LENGTH);
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                                reinterpret_cast<const unsigned char*>(key.data()), iv)) {
            qDebug() << "DecryptInit failed";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    // Вычисляем размер буфера
    out.resize(in.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;

    if (encrypt) {
        if (!EVP_EncryptUpdate(ctx,
                               reinterpret_cast<unsigned char*>(out.data()), &out_len,
                               reinterpret_cast<const unsigned char*>(in.constData()), in.size())) {
            qDebug() << "EncryptUpdate failed";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    } else {
        if (!EVP_DecryptUpdate(ctx,
                               reinterpret_cast<unsigned char*>(out.data()), &out_len,
                               reinterpret_cast<const unsigned char*>(in.constData() + EVP_MAX_IV_LENGTH),
                               in.size() - EVP_MAX_IV_LENGTH)) {
            qDebug() << "DecryptUpdate failed";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    // Финализация (убирается паддинг, который добавлялся при шифровании AES 256)
    int final_len = 0;
    if (encrypt) {
        if (!EVP_EncryptFinal_ex(ctx,
                                 reinterpret_cast<unsigned char*>(out.data()) + out_len, &final_len)) {
            qDebug() << "EncryptFinal failed";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    } else {
        if (!EVP_DecryptFinal_ex(ctx,
                                 reinterpret_cast<unsigned char*>(out.data()) + out_len, &final_len)) {
            qDebug() << "DecryptFinal failed";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    out.resize(out_len + final_len);

    // Добавляем IV в начало при шифровании
    if (encrypt) {
        out.prepend(reinterpret_cast<const char*>(iv), EVP_MAX_IV_LENGTH);
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

void MainWindow::loadDataToTable() {
    dataTable->setRowCount(0);

    for (const CredentialEntry& entry : memoryStorage) {
        int row = dataTable->rowCount();
        dataTable->insertRow(row);

        dataTable->setItem(row, 0, new QTableWidgetItem(entry.hostname));
        dataTable->setItem(row, 1, new QTableWidgetItem("********"));
        dataTable->setItem(row, 2, new QTableWidgetItem("********"));
    }
}

QString MainWindow::requestSecondPin() {
    bool ok;
    QString pin = QInputDialog::getText(this, "Enter PIN", "Please enter your PIN to copy credentials:", QLineEdit::Password, "", &ok);
    if (ok && !pin.isEmpty()) {
        return pin;
    }
    return QString();
}

void MainWindow::handleCellDoubleClick(int row, int column) {
    if (row < 0 || row >= memoryStorage.size()) {
        errorLabelErrorScreen->setText("Invalid cell selected!");
        stackedWidget->setCurrentWidget(errorScreen);
        return;
    }

    const CredentialEntry& entry = memoryStorage[row];
    QString textToCopy;

    // Запрашиваем второй пин-код
    QString secondPin = requestSecondPin();
    if (secondPin.isEmpty()) {
        errorLabelErrorScreen->setText("PIN is required to copy credentials!");
        stackedWidget->setCurrentWidget(errorScreen);
        return;
    }

    // Генерация второго ключа
    QByteArray secondKey = QCryptographicHash::hash(secondPin.toUtf8(), QCryptographicHash::Sha3_256);

    if (column == 1) { // Копируем логин
        QByteArray decryptedLogin = decryptData(entry.encryptedLogin, secondKey);
        textToCopy = QString::fromUtf8(decryptedLogin);
    } else if (column == 2) { // Копируем пароль
        QByteArray decryptedPassword = decryptData(entry.encryptedPassword, secondKey);
        textToCopy = QString::fromUtf8(decryptedPassword);
    } else {
        return; // Не копируем, если кликнули не на логин или пароль
    }

    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(textToCopy);

    errorLabelErrorScreen->setText(QString("Copied to clipboard: %1").arg(textToCopy));
    stackedWidget->setCurrentWidget(errorScreen);

    // Очищаем второй ключ
    secureClear(secondKey);
}

void MainWindow::returnToLogin() {
    memoryStorage.clear();
    dataTable->setRowCount(0);
    filterField->clear();
    stackedWidget->setCurrentWidget(loginScreen);
}
