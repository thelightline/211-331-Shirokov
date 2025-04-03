#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStackedWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QTableWidget>
#include <QVector>
#include <QSortFilterProxyModel>
#include <openssl/evp.h>

struct CredentialEntry {
    QString hostname;
    QByteArray encryptedLogin;
    QByteArray encryptedPassword;
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    QByteArray encryptData(const QByteArray &data, const QByteArray &key);

private:
    QStackedWidget *stackedWidget;
    QWidget *loginScreen, *dataScreen, *errorScreen;
    QLineEdit *passwordField;
    QLineEdit *filterField;
    QLabel *errorLabel;
    QTableWidget *dataTable;
    QVector<CredentialEntry> memoryStorage;
    QSortFilterProxyModel *proxyModel;
    QLabel *errorLabelErrorScreen;
    QByteArray decryptData(const QByteArray &data, const QByteArray &key);
    void secureClear(QByteArray &data);
    void setupLoginScreen();
    void setupDataScreen();
    void setupErrorScreen();
    void checkForDebugger();
    bool do_crypt(const QByteArray &in, QByteArray &out, const QByteArray &key, bool encrypt);
    bool decryptFile(const QByteArray &key);
    void loadDataToTable();
    QString requestSecondPin();
    void createEncryptedFile(const QByteArray &key);

private slots:
    void checkPassword();
    void returnToLogin();
    void handleCellDoubleClick(int row, int column);
    void filterTable(const QString &text);
};

#endif
