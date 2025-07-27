document.addEventListener('DOMContentLoaded', function() {
    // Initialize date pickers
    flatpickr("input[type=date]", {
        altInput: true,
        altFormat: "F j, Y",
        dateFormat: "Y-m-d",
        minDate: "today",
        enableTime: false,
        // Ensure the calendar opens above the input if there's not enough space below
        position: "auto",
        // Allow selecting a range of dates
        mode: "single"
    });
});
