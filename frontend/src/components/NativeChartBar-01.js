import {memo} from 'react';
import BarChart from "@cloudscape-design/components/bar-chart";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";

const ChartComponent = memo(({ series, title, height="300", width="100%", extendedProperties={} }) => {
          
    return (
            <div>
                <BarChart
                      series={series}
                      ariaLabel="Stacked bar chart"
                      height={height}
                      stackedBars
                      xTitle=""
                      yTitle={title}
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
