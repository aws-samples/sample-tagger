// Suppress ResizeObserver errors globally
// This script runs before React loads to catch errors early

(function() {
  'use strict';
  
  // Suppress ResizeObserver errors at the window level
  window.addEventListener('error', function(e) {
    if (e.message && (
        e.message.includes('ResizeObserver') ||
        e.message === 'ResizeObserver loop completed with undelivered notifications.' ||
        e.message === 'ResizeObserver loop limit exceeded'
    )) {
      e.stopImmediatePropagation();
      e.preventDefault();
      return false;
    }
  }, true); // Use capture phase

  // Suppress unhandled promise rejections related to ResizeObserver
  window.addEventListener('unhandledrejection', function(e) {
    if (e.reason && e.reason.message && e.reason.message.includes('ResizeObserver')) {
      e.preventDefault();
      return false;
    }
  });

  // Override console.error to filter ResizeObserver errors
  var originalConsoleError = console.error;
  console.error = function() {
    var args = Array.prototype.slice.call(arguments);
    var errorMessage = args[0] ? args[0].toString() : '';
    
    // Ignore ResizeObserver errors
    if (errorMessage.includes('ResizeObserver')) {
      return;
    }
    
    // Pass through all other errors
    originalConsoleError.apply(console, args);
  };

  console.log('ResizeObserver error suppression initialized');
})();
