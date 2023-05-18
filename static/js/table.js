$(document).ready(function () {
    $('#data-table-user').DataTable();
});

$(document).ready(function() {
    $('#data-table-logs').DataTable({
        "order": [[4, "asc"]],
        "columnDefs": [{
            "targets": [4],
            "type": "date"
        }]
    });
});