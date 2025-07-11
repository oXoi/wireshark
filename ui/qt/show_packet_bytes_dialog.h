/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SHOW_PACKET_BYTES_DIALOG_H
#define SHOW_PACKET_BYTES_DIALOG_H

#include <config.h>
#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <epan/tvbuff.h>
#include "wireshark_dialog.h"

#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QTextCodec>

namespace Ui {
class ShowPacketBytesDialog;
class ShowPacketBytesTextEdit;
}

struct uncompress_list_t {
    QString name;
    tvbuff_t *(*function)(tvbuff_t *, int, int);
};

class ShowPacketBytesDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit ShowPacketBytesDialog(QWidget &parent, CaptureFile &cf);
    ~ShowPacketBytesDialog();

    void addCodecs(const QMap<QString, QTextCodec *> &codecMap);

protected:
    bool eventFilter(QObject *obj, QEvent *event);
    void keyPressEvent(QKeyEvent *event);

private slots:
    void on_sbStart_valueChanged(int value);
    void on_sbEnd_valueChanged(int value);
    void on_cbDecodeAs_currentIndexChanged(int idx);
    void on_cbShowAs_currentIndexChanged(int idx);
    void on_leFind_returnPressed();
    void on_bFind_clicked();
    void on_buttonBox_rejected();

    void showSelected(int start, int end);
    void useRegexFind(bool use_regex);
    void findText(bool go_back = true);
    void helpButton();
    void printBytes();
    void copyBytes();
    void saveAs();

private:
    void setStartAndEnd(int start, int end);
    bool enableShowSelected();
    void updateWidgets(); // Needed for WiresharkDialog?
    void updateHintLabel();
    void sanitizeBuffer(QByteArray &ba, bool handle_CR);
    void symbolizeBuffer(QByteArray &ba);
    QByteArray decodeQuotedPrintable(const uint8_t *bytes, int length);
    void rot13(QByteArray &ba);
    void updateFieldBytes(bool initialization = false);
    void updatePacketBytes();

    Ui::ShowPacketBytesDialog  *ui;

    tvbuff_t   *tvb_;
    QByteArray  field_bytes_;
    QString     hint_label_;
    QString     decode_as_name_;
    QPushButton *print_button_;
    QPushButton *copy_button_;
    QPushButton *save_as_button_;
    bool        use_regex_find_;
    int         start_;
    int         end_;
    QImage      image_;
};

class ShowPacketBytesTextEdit : public QTextEdit
{
    Q_OBJECT

public:
    explicit ShowPacketBytesTextEdit(QWidget *parent = 0) :
        QTextEdit(parent), show_selected_enabled_(true), menus_enabled_(true) { }
    ~ShowPacketBytesTextEdit() { }

    void setShowSelectedEnabled(bool enabled) { show_selected_enabled_ = enabled; }
    void setMenusEnabled(bool enabled) { menus_enabled_ = enabled; }

signals:
    void showSelected(int, int);

private slots:
    void contextMenuEvent(QContextMenuEvent *event);
    void showSelected();
    void showAll();

private:
    bool show_selected_enabled_;
    bool menus_enabled_;
};

#endif // SHOW_PACKET_BYTES_DIALOG_H
