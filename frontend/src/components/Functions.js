import { configuration } from '../pages/Configs';
import { createSearchParams } from "react-router-dom";
import Box from "@cloudscape-design/components/box";

export async function applicationVersionUpdate(params) {
        var version = await gatherVersionJsonFile(params);
        return version;
}


//-- Version Functions
const gatherVersionJsonFile = async (params) => {
    var json = { release : "0.0.0", date : "2023-09-01"}
    try {
        const response = await fetch(configuration["apps-settings"]["version-code-url"] 
        + '?' + createSearchParams({
                                codeId: params.codeId,
                                moduleId: params.moduleId
                                }).toString()
        );
        json = await response.json();
    }
    catch{
        
    }
    return(json);
}



//-- Version Functions
export const gatherLocalVersion = async () => {
    var json = { release : "0.0.0", date : "2023-09-01"}
    try {
        const response = await fetch("./version.json");
        json = await response.json();
    }
    catch{
        
    }
    return(json);
}


//--++ Custom Format Functions

export function customFormatNumber(value,decimalLength) {
        if(value == 0) return '0';
        if(value < 1024) return parseFloat(value).toFixed(decimalLength);
        
        var k = 1024,
        sizes = ['', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'],
        i = Math.floor(Math.log(value) / Math.log(k));
        return parseFloat((value / Math.pow(k, i)).toFixed(decimalLength)) + ' ' + sizes[i];
}

export function customFormatNumberLong(value,decimalLength) {
        if(value == 0) return '0';
        if(value < 1000) return parseFloat(value).toFixed(decimalLength);
        
        var k = 1000,
        sizes = ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'],
        i = Math.floor(Math.log(value) / Math.log(k));
        return parseFloat((value / Math.pow(k, i)).toFixed(decimalLength)) + ' ' + sizes[i];
}


export function customFormatNumberShort(value,decimalLength) {
        
        if (value < 1 && decimalLength == 0 )
          decimalLength=2;

        if (value==0)
          decimalLength=0;

        return value.toLocaleString('en-US', {minimumFractionDigits:decimalLength, maximumFractionDigits:decimalLength}); 

}


export function customFormatDateDifference(startDate, endDate) {
    
        if (startDate !== undefined) {
            
            var endDateValue;
        
            if (endDate === undefined) {
                endDateValue = new Date().valueOf();
            }
            else{
                endDateValue = new Date(endDate).valueOf();
            }
    
            let diffTime = Math.abs(new Date(startDate).valueOf() - endDateValue);
            let days = diffTime / (24*60*60*1000);
            let hours = (days % 1) * 24;
            let minutes = (hours % 1) * 60;
            let secs = (minutes % 1) * 60;
            [days, hours, minutes, secs] = [Math.floor(days), Math.floor(hours), Math.floor(minutes), Math.floor(secs)]
    
            return ( String(minutes) +'m' + " " + String(secs) +'s' );
            
        }
        else 
            return "";
}
    

export function customFormatDateMS(startDate, endDate) {
    
    
    return (Math.abs(new Date(endDate).valueOf() - new Date(startDate).valueOf() )).toLocaleString('en-US', {minimumFractionDigits:0, maximumFractionDigits:0});
    
}

export function customStatusStep(value) {
        
        var result = "";
        switch(value) {
            case "RUNNING" :
                    result = " in-progress";
                    break;
                
        }
        console.log(result);
        return result;
}
    
    


//-- Functions to Format Date

function padTo2Digits(num) {
  return num.toString().padStart(2, '0');
}

export function formatDateLong(date) {
  return (
    [
      date.getFullYear(),
      padTo2Digits(date.getMonth() + 1),
      padTo2Digits(date.getDate()),
    ].join('-') +
    'T' +
    [
      padTo2Digits(date.getHours()),
      padTo2Digits(date.getMinutes()),
      padTo2Digits(date.getSeconds()),
    ].join(':')
  );
}


//-- Date Difference Function
export function customDateDifferenceMinutes(startDate, endDate){
    
            var diff = Math.abs(new Date(startDate) - new Date(endDate));
            return (Math.floor((diff/1000)/60));
            
}
        

//--## Table Functions and Variable


export function getMatchesCountText(count) {
  return count === 1 ? `1 match` : `${count} matches`;
}



export function formatDate(date) {
  const dateFormatter = new Intl.DateTimeFormat('en-US', { dateStyle: 'long' });
  const timeFormatter = new Intl.DateTimeFormat('en-US', { timeStyle: 'short', hour12: false });
  return `${dateFormatter.format(date)}, ${timeFormatter.format(date)}`;
}



export function createLabelFunction(columnName) {
  return ({ sorted, descending }) => {
    const sortState = sorted ? `sorted ${descending ? 'descending' : 'ascending'}` : 'not sorted';
    return `${columnName}, ${sortState}.`;
  };
}



export const paginationLabels = {
  nextPageLabel: 'Next page',
  pageLabel: pageNumber => `Go to page ${pageNumber}`,
  previousPageLabel: 'Previous page',
};




export const pageSizePreference = {
  title: 'Select page size',
  options: [
    { value: 10, label: '10 resources' },
    { value: 20, label: '20 resources' },
  ],
};



export function EmptyState({ title, subtitle, action }) {
  return (
    <Box textAlign="center" color="inherit">
      <Box variant="strong" textAlign="center" color="inherit">
        {title}
      </Box>
      <Box variant="p" padding={{ bottom: 's' }} color="inherit">
        {subtitle}
      </Box>
      {action}
    </Box>
  );
}