/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PREF_MODELS_H
#define PREF_MODELS_H

#include <config.h>

#include <ui/qt/models/tree_model_helpers.h>

#include <epan/prefs.h>

#include <QSortFilterProxyModel>
#include <QTreeView>

class PrefsItem;

class PrefsModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    explicit PrefsModel(QObject * parent = Q_NULLPTR);
    virtual ~PrefsModel();

    enum PrefsModelType {
        Advanced = Qt::UserRole,
        Appearance,
        Layout,
        Columns,
        FontAndColors,
        Capture,
        Expert,
        FilterButtons,
        RSAKeys
    };

    enum PrefsModelColumn {
        colName = 0,
        colStatus,
        colType,
        colValue,
        colLast
    };

    QModelIndex index(int row, int column,
                      const QModelIndex & = QModelIndex()) const;
    QModelIndex parent(const QModelIndex &) const;
    QVariant data(const QModelIndex &index, int role) const;

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    static QString typeToString(PrefsModelType type);
    static QString typeToHelp(PrefsModelType type);

private:
    void populate();

    PrefsItem* root_;
};

class PrefsItem : public ModelHelperTreeItem<PrefsItem>
{
public:
    PrefsItem(module_t *module, pref_t *pref, PrefsItem* parent);
    PrefsItem(const QString name, PrefsItem* parent);
    PrefsItem(PrefsModel::PrefsModelType type, PrefsItem* parent);
    virtual ~PrefsItem();

    QString getName() const {return name_;}
    pref_t* getPref() const {return pref_;}
    int getPrefType() const;
    bool isPrefDefault() const;
    QString getPrefTypeName() const;
    module_t* getModule() const {return module_;}
    QString getModuleName() const;
    QString getModuleTitle() const;
    QString getModuleHelp() const;
    void setChanged(bool changed = true);

private:
    pref_t *pref_;
    module_t *module_;
    QString name_;
    QString help_;
    //set to true if changed during module manipulation
    //Used to determine proper "default" for comparison
    bool changed_;
};

class AdvancedPrefsModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    explicit AdvancedPrefsModel(QObject * parent = Q_NULLPTR);

    enum AdvancedPrefsModelColumn {
        colName = 0,
        colStatus,
        colType,
        colValue,
        colLast
    };

    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;

    void setFilter(const QString& filter);
    void setShowChangedValues(bool show_changed_values);

    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;
    QVariant data(const QModelIndex &index, int role) const;
    Qt::ItemFlags flags(const QModelIndex &index) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole);

    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    //Keep the internals of model hidden from tree
    void setFirstColumnSpanned(QTreeView* tree, const QModelIndex &index = QModelIndex());

protected:
    bool filterAcceptItem(PrefsItem& item) const;

private:

    QString filter_;
    bool show_changed_values_;
    const QChar passwordChar_;
};

class ModulePrefsModel : public QSortFilterProxyModel
{
public:

    explicit ModulePrefsModel(QObject * parent = Q_NULLPTR);

    enum ModulePrefsModelColumn {
        colName = 0,
        colLast
    };

    enum ModulePrefsRoles {
        ModuleName = Qt::UserRole + 1,
        ModuleHelp = Qt::UserRole + 2
    };

    QVariant data(const QModelIndex &index, int role) const;
    Qt::ItemFlags flags(const QModelIndex &index) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;

protected:
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;

private:
    //cache of the translated "Advanced" preference name
    QString advancedPrefName_;
};

extern pref_t *prefFromPrefPtr(void *pref_ptr);

#endif // PREF_MODELS_H
