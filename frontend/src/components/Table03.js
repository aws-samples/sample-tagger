import { memo, useState, useEffect, useCallback, useRef } from 'react';
import { getMatchesCountText, paginationLabels, EmptyState } from './Functions';
import { useCollection } from '@cloudscape-design/collection-hooks';
import { CollectionPreferences, Pagination } from '@cloudscape-design/components';
import TextFilter from "@cloudscape-design/components/text-filter";
import Table from "@cloudscape-design/components/table";
import Header from "@cloudscape-design/components/header";
import Button from "@cloudscape-design/components/button";

const TableComponent = memo(({
    columnsTable,
    visibleContent,
    title,
    description = "",
    tableActions = null,
    footer = null,
    extendedTableProperties = {},
    fetchSize = 500,
    displayPageSize = 20,
    totalRecords = 0,
    selectionType = "multi",
    onFetchData,
    onSelectionChange = () => {},
    onPageChange = () => {},
    loading = false
}) => {

    const [prefetchedData, setPrefetchedData] = useState([]);
    const [displayData, setDisplayData] = useState([]);
    const [currentChunkIndex, setCurrentChunkIndex] = useState(0);
    const [globalPageIndex, setGlobalPageIndex] = useState(1);
    const [actualTotalRecords, setActualTotalRecords] = useState(totalRecords); // Track actual total from API
    const totalPages = Math.ceil(actualTotalRecords / displayPageSize);
    const totalPagesInChunk = Math.ceil(fetchSize / displayPageSize);
    const [isLoading, setIsLoading] = useState(false);
    const [isSorting, setIsSorting] = useState(false);
    const [sortColumn, setSortColumn] = useState(null);
    const [sortDirection, setSortDirection] = useState('ascending');
    const [preferences, setPreferences] = useState({ 
        pageSize: displayPageSize, 
        visibleContent: visibleContent 
    });

    // Use ref to store the callback to avoid dependency issues
    const onSelectionChangeRef = useRef(onSelectionChange);
    useEffect(() => {
        onSelectionChangeRef.current = onSelectionChange;
    }, [onSelectionChange]);

    const visibleContentPreference = {
        title: 'Select visible content',
        options: [
            {
                label: 'Main properties',
                options: columnsTable.map(({ id, header }) => ({ 
                    id, 
                    label: header, 
                    editable: id !== 'id' 
                })),
            },
        ],
    };

    const collectionPreferencesProps = {
        visibleContentPreference,
        cancelLabel: 'Cancel',
        confirmLabel: 'Confirm',
        title: 'Preferences',
    };


    const fetchChunk = useCallback(async (chunkIndex) => {
        if (!onFetchData) return;
        
        setIsLoading(true);
        try {
            const page = chunkIndex;
            const limit = fetchSize;
            const response = await onFetchData({ page, limit });
            
            if (response && response.resources) {
                setPrefetchedData(response.resources);
                // Update actual total from API response
                if (response.totalRecords !== undefined) {
                    setActualTotalRecords(response.totalRecords);
                }
                return response.resources;
            } else {
                setPrefetchedData([]);
                return [];
            }
        } catch (error) {
            console.error('Error fetching chunk:', error);
            setPrefetchedData([]);
            return [];
        } finally {
            setIsLoading(false);
        }
    }, [onFetchData, fetchSize]);

    const displayPage = useCallback((pageIndex, dataSource) => {
        const internalPageIndex = pageIndex % totalPagesInChunk;
        const start = internalPageIndex * displayPageSize;
        const end = start + displayPageSize;
        const pageData = dataSource.slice(start, end);
        setDisplayData(pageData);
    }, [displayPageSize, totalPagesInChunk]);


    // Handle page change
    const handlePageChange = useCallback(async (newPageIndex) => {
        const newChunkIndex = Math.floor((newPageIndex - 1) / totalPagesInChunk);
        
        if (newChunkIndex !== currentChunkIndex) {
            setCurrentChunkIndex(newChunkIndex);
            const newData = await fetchChunk(newChunkIndex);
            displayPage(newPageIndex - 1, newData);
        } else {
            displayPage(newPageIndex - 1, prefetchedData);
        }
        
        setGlobalPageIndex(newPageIndex);
        onPageChange({
            pageIndex: newPageIndex,
            chunkIndex: newChunkIndex,
            totalPages: totalPages
        });
    }, [currentChunkIndex, totalPagesInChunk, fetchChunk, displayPage, prefetchedData, totalPages, onPageChange]);

    const handleSortingChange = useCallback((event) => {
        const { sortingColumn, isDescending } = event.detail;
        
        if (!sortingColumn || !sortingColumn.sortingField) return;
        
        setIsSorting(true);
        setSortColumn(sortingColumn.sortingField);
        setSortDirection(isDescending ? 'descending' : 'ascending');
        
        setTimeout(() => {
            const sorted = [...prefetchedData].sort((a, b) => {
                const aVal = a[sortingColumn.sortingField];
                const bVal = b[sortingColumn.sortingField];
                
                if (aVal == null && bVal == null) return 0;
                if (aVal == null) return 1;
                if (bVal == null) return -1;
                
                let comparison = 0;
                if (typeof aVal === 'string' && typeof bVal === 'string') {
                    comparison = aVal.localeCompare(bVal);
                } else if (typeof aVal === 'number' && typeof bVal === 'number') {
                    comparison = aVal - bVal;
                } else {
                    comparison = String(aVal).localeCompare(String(bVal));
                }
                
                return isDescending ? -comparison : comparison;
            });
            
            setPrefetchedData(sorted);
            displayPage(globalPageIndex - 1, sorted);
            setIsSorting(false);
        }, 0);
    }, [prefetchedData, globalPageIndex, displayPage]);

    // Initial load - only run once on mount
    useEffect(() => {
        fetchChunk(0).then(data => {
            if (data && data.length > 0) {
                const pageData = data.slice(0, displayPageSize);
                setDisplayData(pageData);
            }
        });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []); // Empty dependency array - only run on mount


    const { items, actions, filteredItemsCount, collectionProps, filterProps } = useCollection(
        displayData,
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
            pagination: { pageSize: displayData.length || 1000 },
            sorting: {},
            selection: {
                keepSelection: false, // Clear selection on page change
            },
        }
    );

    // Store the collection's onSelectionChange handler
    const collectionOnSelectionChange = collectionProps.onSelectionChange;

    // Intercept selection change to call parent callback
    // Use ref for parent callback to avoid recreating this handler
    const handleSelectionChangeIntercept = useCallback((event) => {
        // Call the collection hook's handler first to update its internal state
        if (collectionOnSelectionChange) {
            collectionOnSelectionChange(event);
        }
        
        // Then call our custom handler using ref
        const items = event.detail.selectedItems;
        if (onSelectionChangeRef.current) {
            onSelectionChangeRef.current(items);
        }
    }, [collectionOnSelectionChange]);

    const counterText = `(${actualTotalRecords.toLocaleString('en-US')})`;

    return (
        <Table
            {...collectionProps}
            {...extendedTableProperties}
            selectionType={selectionType}
            onSelectionChange={handleSelectionChangeIntercept}
            header={
                <Header
                    variant="h3"
                    counter={counterText}
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
                    currentPageIndex={globalPageIndex}
                    onChange={({ detail }) => handlePageChange(detail.currentPageIndex)}
                    pagesCount={totalPages}
                    ariaLabels={paginationLabels}
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
            footer={footer}
            onSortingChange={handleSortingChange}
            sortingColumn={sortColumn ? { sortingField: sortColumn } : undefined}
            sortingDescending={sortDirection === 'descending'}
            loading={loading || isLoading || isSorting}
            loadingText={isSorting ? "Sorting..." : "Loading records..."}
            resizableColumns
            stickyHeader
        />
    );
});

export default TableComponent;
