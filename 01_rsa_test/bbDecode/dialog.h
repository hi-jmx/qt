#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>
#include "openssl/rsa.h"
#include "qlabel.h"
namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = 0);
    ~Dialog();

    int rsaResult;

    QString setDir();
    RSA *createRSA(unsigned char *key, int publi);

    int public_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted);
    int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted);
    int private_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted);
    int public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted);

    int public_encrypt(QString &data, QString &keystr, QString &encrypted);
    int private_decrypt(QString &data, QString &keystr, QString &decrypted);
    int private_encrypt(QString &data, QString &keystr, QString &encrypted);
    int public_decrypt(QString &data, QString &keystr, QString &decrypted);
    int fileDecode(QString fileName);
    QString readFromFile();
    void writeToFile(QString outPath);
    void Delay_MSec(unsigned int msec);
private slots:
    void on_pb_min_clicked();

    void on_pb_close_clicked();

    void on_pb_add_clicked();

    void on_pb_clear_clicked();
    void addFileToTable(QString fileName);
    void restartClicked();
    void folderClicked();
    void close_1Clicked();
    void on_pb_start_clicked();

    void on_pb_dir_clicked();

signals:
    void sig_fileName(QString fileName);
private:
    Ui::Dialog *ui;
    QString lastPath;
    void uiInit();
    void initTable();
    QString ReadStyleSheet(const QString &styleName);
    bool setStyle(QWidget *widget, QString qssFile);
    void decodeUseIndex(int row);

protected:
    void showEvent(QShowEvent *);
    virtual void mousePressEvent(QMouseEvent *event);
    virtual void mouseMoveEvent(QMouseEvent *event);
    virtual void mouseReleaseEvent(QMouseEvent *event);
private:
    bool m_Drag;
    QPoint m_DragPosition;
};

#endif // DIALOG_H
