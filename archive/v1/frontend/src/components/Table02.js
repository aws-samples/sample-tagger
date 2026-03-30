import {memo,useState} from 'react';
import {  getMatchesCountText, paginationLabels, pageSizePreference, EmptyState } from './Functions';

import { useCollection } from '@cloudscape-design/collection-hooks';
import {CollectionPreferences,Pagination } from '@cloudscape-design/components';
import TextFilter from "@cloudscape-design/components/text-filter";

import Table from "@cloudscape-design/components/table";
import Header from "@cloudscape-design/components/header";
import Button from "@cloudscape-design/components/button";

                                                                
const TableComponent = memo(({columnsTable,visibleContent, dataset, title, description = "", onSelectionItem = () => {}, onPaginationChange = () => {}, totalPages=1, pageSize = 10, totalRecords=0, pageId = 1, extendedTableProperties = {}, tableActions = null  }) => {

    const [currentPageIndex,setCurrentPageIndex] = useState(1);

    const [selectedItems,setSelectedItems] = useState([{ identifier: "" }]);

    const visibleContentPreference = {
              title: 'Select visible content',
              options: [
                {
                  label: 'Main properties',
                  options: columnsTable.map(({ id, header }) => ({ id, label: header, editable: id !== 'id' })),
                },
              ],
    };

   const collectionPreferencesProps = {            
            visibleContentPreference,
            cancelLabel: 'Cancel',
            confirmLabel: 'Confirm',
            title: 'Preferences',
    };
    
    
    const [preferences, setPreferences] = useState({ pageSize: pageSize, visibleContent: visibleContent });
    
    const { items, actions, filteredItemsCount, collectionProps, filterProps, paginationProps } = useCollection(
                dataset,
                {
                  filtering: {
                    empty: <EmptyState title="No records" />,
                    noMatch: (
                      <EmptyState
                        title="No matches"
                        action={<Button onClick={() => actions.setFiltering('')}>Clear filter</Button>}
                      />
                    ),
                  },
                  pagination: { pageSize: preferences.pageSize },
                  sorting: {},
                  selection: {},
                }
    );
    
    function onSelectionChange(item){
      onSelectionItem(item);
    }
    

    function onPaginationChangeInternal(item){
      onPaginationChange(item);
    }
    

    

    //pagination={<Pagination {...paginationProps} ariaLabels={paginationLabels} />}
    
    return (
                <Table
                      {...collectionProps}
                      selectionType="single"
                      header={
                        <Header
                          variant="h3"
                          counter= {"(" + totalRecords.toLocaleString('en-US', {minimumFractionDigits:0, maximumFractionDigits:0})   + ")"} 
                          description={description}
                          actions={tableActions}
                        >
                          {title}
                        </Header>
                      }
                      columnDefinitions={columnsTable}
                      visibleColumns={preferences.visibleContent}
                      items={items}
                      pagination={
                          <Pagination
                                currentPageIndex={pageId}
                                onChange={({ detail }) => {
                                  setCurrentPageIndex(detail.currentPageIndex);
                                  onPaginationChangeInternal(detail.currentPageIndex);
                                  }
                                }
                                pagesCount={totalPages}
                              />                        
                      }
                      filter={
                        <TextFilter
                          {...filterProps}
                          countText={getMatchesCountText(filteredItemsCount)}
                          filteringAriaLabel="Filter records"
                        />
                      }
                      preferences={
                        <CollectionPreferences
                          {...collectionPreferencesProps}
                          preferences={preferences}
                          onConfirm={({ detail }) => setPreferences(detail)}
                        />
                      }
                      onSelectionChange={({ detail }) => {
                          onSelectionChange(detail.selectedItems);
                          setSelectedItems(detail.selectedItems);
                          }
                        }
                      selectedItems={selectedItems}
                      resizableColumns
                      stickyHeader
                      loadingText="Loading records"
                      
                      {...extendedTableProperties}
                    />

           );
});

export default TableComponent;
