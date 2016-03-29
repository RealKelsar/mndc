#ifndef PREFERENCES_H
#define PREFERENCES_H

#include <QDialog>
#include <QString>
#include <QHash>

namespace Ui {
    class DialogSettings;
}

class Preferences : public QDialog
{
    Q_OBJECT

public:
    Preferences(QWidget *parent = 0);
    ~Preferences();
    void setConfig( QHash<QString, QString> config);
    void setConfig();
    QHash<QString, QString> getConfig();

private:
    Ui::DialogSettings *ui;
    QHash<QString, QString> config;
    void search( QString);
    void updateNetworkConfig();

public slots:
    void searchTraceroute();
    void searchPing();
    void searchPing6();
    void searchWhois();
    void searchDig();
    void searchNmap();
    void searchSudo();

signals:

};

#endif // PREFERENCES_H
