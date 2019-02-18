#pragma once

#include <QtCore/QCoreApplication>
#include <QtCore/QThread>
#include <QtCore/QDebug>

class QtHandle : public QObject {
	Q_OBJECT
public:
	QtHandle() {
		QCoreApplication::setOrganizationName("StarburstComputing");
		QCoreApplication::setApplicationName("Moonvdec");
	}

	void start() {
		if(thread == nullptr) {
			thread = new QThread();
			connect(thread, SIGNAL(started()), this, SLOT(onLaunched()), Qt::DirectConnection);
			thread->start();
		}
	}

	void stop() {
		if(thread != nullptr) {
			if(thread->isRunning()) {
				thread->quit();
				thread->wait();
			}
			delete thread;
			thread = nullptr;
		}
	}

	static QtHandle& instance() {
		if(_inst == nullptr) {
			_inst = new QtHandle;
		}
		return *_inst;
	}

private slots:
	void onLaunched() {
		if(QCoreApplication::instance() == nullptr) {
			app = new QCoreApplication(argc, nullptr);
			app->exec();
		}
	}

private:
	static QtHandle* _inst;

	int argc = 0;
	QCoreApplication* app = nullptr;
	QThread* thread = nullptr;
};

