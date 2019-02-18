#pragma once

#include "identitymanager.h"

#include <../common-c/Limelight.h>

#include <QtCore/QUrl>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>

class NvApp
{
public:
    bool operator==(const NvApp& other) const
    {
        return id == other.id;
    }

    bool isInitialized()
    {
        return id != 0 && !name.isEmpty();
    }

    int id;
    QString name;
    bool hdrSupported;
};

Q_DECLARE_METATYPE(NvApp)

class NvDisplayMode
{
public:
    bool operator==(const NvDisplayMode& other) const
    {
        return width == other.width &&
                height == other.height &&
                refreshRate == other.refreshRate;
    }

    int width;
    int height;
    int refreshRate;
};

class GfeHttpResponseException : public std::exception
{
public:
    GfeHttpResponseException(int statusCode, QString message) :
        m_StatusCode(statusCode),
        m_StatusMessage(message)
    {

    }

    const char* what() const throw()
    {
        return m_StatusMessage.toUtf8();
    }

    const char* getStatusMessage() const
    {
        return m_StatusMessage.toUtf8();
    }

    int getStatusCode() const
    {
        return m_StatusCode;
    }

    QString toQString() const
    {
        return m_StatusMessage + " (Error " + QString::number(m_StatusCode) + ")";
    }

private:
    int m_StatusCode;
    QString m_StatusMessage;
};

class QtNetworkReplyException : public std::exception
{
public:
    QtNetworkReplyException(QNetworkReply::NetworkError error, QString errorText) :
        m_Error(error),
        m_ErrorText(errorText)
    {

    }

    const char* what() const throw()
    {
        return m_ErrorText.toUtf8();
    }

    const char* getErrorText() const
    {
        return m_ErrorText.toUtf8();
    }

    QNetworkReply::NetworkError getError() const
    {
        return m_Error;
    }

    QString toQString() const
    {
        return m_ErrorText + " (Error " + QString::number(m_Error) + ")";
    }

private:
    QNetworkReply::NetworkError m_Error;
    QString m_ErrorText;
};

class NvHTTP
{
public:
    enum NvLogLevel {
        NONE,
        ERROR,
        VERBOSE
    };

    explicit NvHTTP(QString address);

    static
    int
    getCurrentGame(QString serverInfo);

    QString
    getServerInfo(NvLogLevel logLevel);

    static
    void
    verifyResponseStatus(QString xml);

    static
    QString
    getXmlString(QString xml,
                 QString tagName);

    static
    QByteArray
    getXmlStringFromHex(QString xml,
                        QString tagName);

    QString
    openConnectionToString(QUrl baseUrl,
                           QString command,
                           QString arguments,
                           bool enableTimeout,
                           NvLogLevel logLevel = NvLogLevel::VERBOSE);

    static
    QVector<int>
    parseQuad(QString quad);

    void
    quitApp();

    void
    resumeApp(PSTREAM_CONFIGURATION streamConfig);

    void
    launchApp(int appId,
              PSTREAM_CONFIGURATION streamConfig,
              bool localAudio);

    QVector<NvApp>
    getAppList();

    static
    QVector<NvDisplayMode>
    getDisplayModeList(QString serverInfo);

    QUrl m_BaseUrlHttp;
    QUrl m_BaseUrlHttps;
private:
    QNetworkReply*
    openConnection(QUrl baseUrl,
                   QString command,
                   QString arguments,
                   bool enableTimeout,
                   NvLogLevel logLevel);

    QString m_Address;
    QNetworkAccessManager m_Nam;
};
