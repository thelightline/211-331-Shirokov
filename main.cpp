#include "mainwindow.h"
#include <QApplication>
#include <QStyleFactory>
#include <QPalette>
#include <QMessageBox>
#include <QCryptographicHash>
#include <QByteArray>
#include <windows.h>
#include <winnt.h>
#include <cstdint>

// Функция проверки целостности .text сегмента
bool checkCodeIntegrity() {
    // 1. Получаем базовый адрес модуля
    uintptr_t imageBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));

    // 2. Парсим PE-заголовки
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
    PIMAGE_NT_HEADERS peHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(imageBase + dosHeader->e_lfanew);

    // 3. Определяем адрес и размер сегмента .text
    uintptr_t textBase = imageBase + peHeader->OptionalHeader.BaseOfCode;
    DWORD textSize = peHeader->OptionalHeader.SizeOfCode;

    // 4. Вычисляем хеш
    QByteArray textSegment(reinterpret_cast<const char*>(textBase), textSize);
    QByteArray currentHash = QCryptographicHash::hash(textSegment, QCryptographicHash::Sha256).toBase64();
    const QByteArray referenceHash = "AGuuRkZr873gcq3dUjwTX6dawF74W6NqlyBc2ALAEKQ=";

    QMessageBox::information(nullptr, "Debug", "Хеш: " + currentHash);

    return (currentHash == referenceHash);
}

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    a.setStyle(QStyleFactory::create("Fusion"));
    // Проверка на отладчик
//    if (IsDebuggerPresent()) {
//        QMessageBox::warning(
//            nullptr,
//            "Обнаружен отладчик",
//            "Внимание: приложение запущено под отладчиком!",
//            QMessageBox::Ok
//            );
//    }

    // Проверка целостности кода
    if (!checkCodeIntegrity()) {
        QMessageBox::critical(
            nullptr,
            "Ошибка целостности",
            "Обнаружена модификация приложения!",
            QMessageBox::Ok
            );
        return 1;
    }

    QPalette palette;
    palette.setColor(QPalette::Window, QColor(30, 30, 30));
    palette.setColor(QPalette::WindowText, Qt::white);
    palette.setColor(QPalette::Base, QColor(45, 45, 45));
    palette.setColor(QPalette::AlternateBase, QColor(53, 53, 53));
    palette.setColor(QPalette::ToolTipBase, QColor(60, 60, 60));
    palette.setColor(QPalette::ToolTipText, Qt::white);
    palette.setColor(QPalette::Text, Qt::white);
    palette.setColor(QPalette::Button, QColor(45, 45, 45));
    palette.setColor(QPalette::ButtonText, Qt::white);
    palette.setColor(QPalette::BrightText, Qt::red);
    palette.setColor(QPalette::Highlight, QColor(42, 130, 218));
    palette.setColor(QPalette::HighlightedText, Qt::black);
    a.setPalette(palette);

    MainWindow w;
    w.show();
    return a.exec();
}
