import {memo} from 'react';
import PieChart from "@cloudscape-design/components/pie-chart";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";

const ChartComponent = memo(({ series, title, height="300", width="100%", extendedProperties={} }) => {
          
    return (
            <div>
                <PieChart                        
                        hideFilter
                        data={series}
                        detailPopoverContent={(datum, sum) => [
                          { key: "Resource count", value: datum.value },
                          {
                            key: "Percentage",
                            value: `${((datum.value / sum) * 100).toFixed(
                              0
                            )}%`
                          },
                          { key: "Last update on", value: datum.lastUpdate }
                        ]}
                        segmentDescription={(datum, sum) =>
                          `${datum.value} resources, ${(
                            (datum.value / sum) *
                            100
                          ).toFixed(0)}%`
                        }
                        ariaDescription="Pie chart showing how many resources are currently in which state."
                        ariaLabel="Pie chart"
                        empty={
                          <Box textAlign="center" color="inherit">
                            <b>No data available</b>
                            <Box variant="p" color="inherit">
                              There is no data available
                            </Box>
                          </Box>
                        }
                        noMatch={
                          <Box textAlign="center" color="inherit">
                            <b>No matching data</b>
                            <Box variant="p" color="inherit">
                              There is no matching data to display
                            </Box>
                            <Button>Clear filter</Button>
                          </Box>
                        }
                        {...extendedProperties}
                      />
            </div>
           );
});

export default ChartComponent;
