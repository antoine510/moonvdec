#pragma once

#include "nvhttp.h"

#include <QtCore/QThread>
#include <QtCore/QReadWriteLock>
#include <QtCore/QSettings>
#include <QtCore/QRunnable>

class NvComputer
{
    friend class PcMonitorThread;
    friend class ComputerManager;
    friend class PendingQuitTask;

private:
    void sortAppList();

    bool pendingQuit;

public:
    explicit NvComputer(QString address, QString serverInfo);

    explicit NvComputer(QSettings& settings);

	bool updateAppList();

    bool
    update(NvComputer& that);

    QVector<QString>
    uniqueAddresses();

    void
    serialize(QSettings& settings);

    enum PairState
    {
        PS_UNKNOWN,
        PS_PAIRED,
        PS_NOT_PAIRED
    };

    enum ComputerState
    {
        CS_UNKNOWN,
        CS_ONLINE,
        CS_OFFLINE
    };

    // Ephemeral traits
    ComputerState state;
    PairState pairState;
    QString activeAddress;
    int currentGameId;
    QString gfeVersion;
    QString appVersion;
    QVector<NvDisplayMode> displayModes;
    int maxLumaPixelsHEVC;
    int serverCodecModeSupport;
    QString gpuModel;

    // Persisted traits
    QString localAddress;
    QString remoteAddress;
    QString manualAddress;
    QByteArray macAddress;
    QString name;
    QString uuid;
    QVector<NvApp> appList;

    // Synchronization
    QReadWriteLock lock;
};
