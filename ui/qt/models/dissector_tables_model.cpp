/* dissector_tables_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/dissector_tables_model.h>
#include <epan/ftypes/ftypes.h>
#include <epan/packet.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/variant_pointer.h>
#include "main_application.h"

static const char* CUSTOM_TABLE_NAME = "Custom Tables";
static const char* INTEGER_TABLE_NAME = "Integer Tables";
static const char* STRING_TABLE_NAME = "String Tables";
static const char* HEURISTIC_TABLE_NAME = "Heuristic Tables";

class IntegerTablesItem : public DissectorTablesItem
{
public:
    IntegerTablesItem(unsigned int value, ftenum_t type, int display, QString dissectorDescription, DissectorTablesItem* parent);
    virtual ~IntegerTablesItem();

    virtual bool lessThan(DissectorTablesItem &right) const;

protected:
    unsigned int value_;
};


DissectorTablesItem::DissectorTablesItem(QString tableName, QString dissectorDescription, DissectorTablesItem* parent) :
    ModelHelperTreeItem<DissectorTablesItem>(parent),
    tableName_(tableName),
    dissectorDescription_(dissectorDescription)
{
}

DissectorTablesItem::~DissectorTablesItem()
{
}

bool DissectorTablesItem::lessThan(DissectorTablesItem &right) const
{
    if (tableName().compare(right.tableName(), Qt::CaseInsensitive) < 0)
        return true;

    return false;
}


IntegerTablesItem::IntegerTablesItem(unsigned int value, ftenum_t type, int display, QString dissectorDescription, DissectorTablesItem* parent)
    : DissectorTablesItem(QString(), dissectorDescription, parent)
    , value_(value)
{
    switch (display)
    {
        case BASE_OCT:
            tableName_ = QStringLiteral("0%1").arg(value, 0, 8);
            break;
        case BASE_HEX:
            int field_width;

            switch (type)
            {
                case FT_UINT8:
                    field_width = 2;
                    break;
                case FT_UINT16:
                    field_width = 4;
                    break;
                case FT_UINT24:
                    field_width = 6;
                    break;
                case FT_UINT32:
                default:
                    field_width = 8;
                    break;
            }

            tableName_ = int_to_qstring(value, field_width, 16);
            break;
        case BASE_DEC:
        default:
            tableName_ = QString::number(value);
            break;
    }
}

IntegerTablesItem::~IntegerTablesItem()
{
}

bool IntegerTablesItem::lessThan(DissectorTablesItem &right) const
{
    if (value_ == ((IntegerTablesItem&)right).value_) {
        return DissectorTablesItem::lessThan(right);
    }

    if (value_ < ((IntegerTablesItem&)right).value_) {
        return true;
    }

    return false;
}

DissectorTablesModel::DissectorTablesModel(QObject *parent) :
    QAbstractItemModel(parent),
    root_(new DissectorTablesItem(QStringLiteral("ROOT"), QStringLiteral("ROOT"), NULL))
{
    populate();
}

DissectorTablesModel::~DissectorTablesModel()
{
    delete root_;
}

int DissectorTablesModel::rowCount(const QModelIndex &parent) const
{
    DissectorTablesItem *parent_item;
    if (parent.column() > 0)
        return 0;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<DissectorTablesItem*>(parent.internalPointer());

    if (parent_item == NULL)
        return 0;

    return parent_item->childCount();
}

int DissectorTablesModel::columnCount(const QModelIndex&) const
{
    return colLast;
}

QModelIndex DissectorTablesModel::parent(const QModelIndex& index) const
{
    if (!index.isValid())
        return QModelIndex();

    DissectorTablesItem* item = static_cast<DissectorTablesItem*>(index.internalPointer());
    if (item != NULL) {
        DissectorTablesItem* parent_item = item->parentItem();
        if (parent_item != NULL) {
            if (parent_item == root_)
                return QModelIndex();

            return createIndex(parent_item->row(), 0, parent_item);
        }
    }

    return QModelIndex();
}

QModelIndex DissectorTablesModel::index(int row, int column, const QModelIndex& parent) const
{
    if (!hasIndex(row, column, parent))
        return QModelIndex();

    DissectorTablesItem *parent_item, *child_item;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<DissectorTablesItem*>(parent.internalPointer());

    Q_ASSERT(parent_item);

    child_item = parent_item->child(row);
    if (child_item) {
        return createIndex(row, column, child_item);
    }

    return QModelIndex();
}

QVariant DissectorTablesModel::data(const QModelIndex &index, int role) const
{
    if ((!index.isValid()) || (role != Qt::DisplayRole))
        return QVariant();

    DissectorTablesItem* item = static_cast<DissectorTablesItem*>(index.internalPointer());
    if (item == NULL)
        return QVariant();

    switch ((enum DissectorTablesColumn)index.column())
    {
    case colTableName:
        return item->tableName();
    case colDissectorDescription:
        return item->dissectorDescription();
    default:
        break;
    }

    return QVariant();
}

static void gatherProtocolDecodes(const char *short_name, ftenum_t selector_type, void *key, void *value, void *item_ptr)
{
    DissectorTablesItem* pdl_ptr = (DissectorTablesItem*)item_ptr;
    if (pdl_ptr == NULL)
        return;

    dtbl_entry_t       *dtbl_entry = (dtbl_entry_t*)value;
    dissector_handle_t  handle = dtbl_entry_get_handle(dtbl_entry);
    const QString       dissector_description = dissector_handle_get_description(handle);
    int                 display = get_dissector_table_param(short_name);
    DissectorTablesItem *ti = NULL;

    switch (selector_type) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        ti = new IntegerTablesItem(GPOINTER_TO_UINT(key), selector_type, display, dissector_description, pdl_ptr);
        pdl_ptr->prependChild(ti);
        break;

    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
    case FT_STRINGZTRUNC:
        ti = new DissectorTablesItem((const char *)key, dissector_description, pdl_ptr);
        pdl_ptr->prependChild(ti);
        break;

    case FT_BYTES:
        ti = new DissectorTablesItem(dissector_handle_get_description(handle), dissector_description, pdl_ptr);
        pdl_ptr->prependChild(ti);
        break;

    default:
        break;
    }
}

struct tables_root
{
    DissectorTablesItem* custom_table;
    DissectorTablesItem* integer_table;
    DissectorTablesItem* string_table;
};

static void gatherTableNames(const char *short_name, const char *table_name, void *model_ptr)
{
    struct tables_root* tables = (struct tables_root*)model_ptr;
    if (model_ptr == NULL)
        return;

    ftenum_t selector_type = get_dissector_table_selector_type(short_name);
    DissectorTablesItem *dt_ti = NULL;

    switch (selector_type) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        dt_ti = new DissectorTablesItem(table_name, short_name, tables->integer_table);
        tables->integer_table->prependChild(dt_ti);
        break;
    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
    case FT_STRINGZTRUNC:
        dt_ti = new DissectorTablesItem(table_name, short_name, tables->string_table);
        tables->string_table->prependChild(dt_ti);
        break;
    case FT_BYTES:
        dt_ti = new DissectorTablesItem(table_name, short_name, tables->custom_table);
        tables->custom_table->prependChild(dt_ti);
        break;
    default:
        // Assert?
        return;
    }

    dissector_table_foreach(short_name, gatherProtocolDecodes, dt_ti);
}

static void gatherHeurProtocolDecodes(const char *, struct heur_dtbl_entry *dtbl_entry, void *list_ptr)
{
    DissectorTablesItem* hdl_ptr = (DissectorTablesItem*)list_ptr;
    if (hdl_ptr == NULL)
        return;

    if (dtbl_entry->protocol) {
        QString longName = proto_get_protocol_long_name(dtbl_entry->protocol);
        QString heurDisplayName = dtbl_entry->display_name;
        if (! heurDisplayName.isEmpty())
            longName.append(QStringLiteral(" (%1)").arg(heurDisplayName));

        DissectorTablesItem *heur = new DissectorTablesItem(longName, proto_get_protocol_short_name(dtbl_entry->protocol), hdl_ptr);
        hdl_ptr->prependChild(heur);
    }
}

static void gatherHeurTableNames(const char *table_name, heur_dissector_list *list, void *heur_tables)
{
    DissectorTablesItem* table = (DissectorTablesItem*)heur_tables;
    if (table == NULL)
        return;

    QString desc_name = table_name;
    if (list) {
        const char *desc = heur_dissector_list_get_description(list);
        if (desc) desc_name = desc;
    }
    DissectorTablesItem *heur = new DissectorTablesItem(desc_name, table_name, table);
    table->prependChild(heur);

    if (list) {
        heur_dissector_table_foreach(table_name, gatherHeurProtocolDecodes, heur);
    }
}

void DissectorTablesModel::populate()
{
    beginResetModel();

    struct tables_root tables;

    tables.custom_table = new DissectorTablesItem(tr(CUSTOM_TABLE_NAME), QString(""), root_);
    root_->prependChild(tables.custom_table);
    tables.integer_table = new DissectorTablesItem(tr(INTEGER_TABLE_NAME), QString(""), root_);
    root_->prependChild(tables.integer_table);
    tables.string_table = new DissectorTablesItem(tr(STRING_TABLE_NAME), QString(""), root_);
    root_->prependChild(tables.string_table);

    dissector_all_tables_foreach_table(gatherTableNames, &tables, NULL);

    DissectorTablesItem* heuristic_table = new DissectorTablesItem(tr(HEURISTIC_TABLE_NAME), QString(""), root_);
    root_->prependChild(heuristic_table);

    dissector_all_heur_tables_foreach_table(gatherHeurTableNames, heuristic_table, NULL);

    endResetModel();
}





DissectorTablesProxyModel::DissectorTablesProxyModel(QObject * parent)
: QSortFilterProxyModel(parent),
tableName_(tr("Table Type")),
dissectorDescription_(),
filter_()
{
}

QVariant DissectorTablesProxyModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {

        switch ((enum DissectorTablesModel::DissectorTablesColumn)section) {
        case DissectorTablesModel::colTableName:
            return tableName_;
        case DissectorTablesModel::colDissectorDescription:
            return dissectorDescription_;
        default:
            break;
        }
    }
    return QVariant();
}

bool DissectorTablesProxyModel::lessThan(const QModelIndex &left, const QModelIndex &right) const
{
    //Use DissectorTablesItem directly for better performance
    DissectorTablesItem* left_item = static_cast<DissectorTablesItem*>(left.internalPointer());
    DissectorTablesItem* right_item = static_cast<DissectorTablesItem*>(right.internalPointer());

    if ((left_item != NULL) && (right_item != NULL)) {
        return left_item->lessThan(*right_item);
    }

    return false;
}

// NOLINTNEXTLINE(misc-no-recursion)
bool DissectorTablesProxyModel::filterAcceptItem(DissectorTablesItem& item) const
{
    if (filter_.isEmpty())
        return true;

    if (item.tableName().contains(filter_, Qt::CaseInsensitive) || item.dissectorDescription().contains(filter_, Qt::CaseInsensitive))
        return true;

    DissectorTablesItem *child_item;
    for (int child_row = 0; child_row < item.childCount(); child_row++)
    {
        child_item = item.child(child_row);
        // We recurse here, but the tree is only three levels deep
        if ((child_item != NULL) && (filterAcceptItem(*child_item)))
            return true;
    }

    return false;
}

bool DissectorTablesProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex nameIdx = sourceModel()->index(sourceRow, DissectorTablesModel::colTableName, sourceParent);
    DissectorTablesItem* item = static_cast<DissectorTablesItem*>(nameIdx.internalPointer());
    if (item == NULL)
        return false;

    if (filterAcceptItem(*item))
        return true;

    return false;
}

void DissectorTablesProxyModel::setFilter(const QString& filter)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
    beginFilterChange();
#endif
    filter_ = filter;
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    endFilterChange(QSortFilterProxyModel::Direction::Rows);
#else
    invalidateFilter();
#endif
}

void DissectorTablesProxyModel::adjustHeader(const QModelIndex &currentIndex)
{
    tableName_ = tr("Table Type");
    dissectorDescription_ = QString();
    if (currentIndex.isValid() && currentIndex.parent().isValid()) {
        QString table;

        if (currentIndex.parent().parent().isValid()) {
            table = data(index(currentIndex.parent().parent().row(), DissectorTablesModel::colTableName), Qt::DisplayRole).toString();
            if ((table.compare(CUSTOM_TABLE_NAME) == 0) ||
                (table.compare(STRING_TABLE_NAME) == 0)) {
                tableName_ = tr("String");
                dissectorDescription_ = tr("Dissector Description");
            } else if (table.compare(INTEGER_TABLE_NAME) == 0) {
                tableName_ = tr("Integer");
                dissectorDescription_ = tr("Dissector Description");
            } else if (table.compare(HEURISTIC_TABLE_NAME) == 0) {
                tableName_ = tr("Protocol");
                dissectorDescription_ = tr("Short Name");
            }
        } else {
            table = data(index(currentIndex.parent().row(), DissectorTablesModel::colTableName), Qt::DisplayRole).toString();
            if ((table.compare(CUSTOM_TABLE_NAME) == 0) ||
                (table.compare(INTEGER_TABLE_NAME) == 0) ||
                (table.compare(STRING_TABLE_NAME) == 0)) {
                tableName_ = tr("Table Name");
                dissectorDescription_ = tr("Selector Name");
            } else if (table.compare(HEURISTIC_TABLE_NAME) == 0) {
                tableName_ = tr("Protocol");
                dissectorDescription_ = tr("Short Name");
            }
        }
    }


    emit headerDataChanged(Qt::Vertical, 0, 1);
}
