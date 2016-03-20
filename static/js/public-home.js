$(document).ready(function() {
    $('#req-btn').click(function() {
        console.log('sending request to authenticated API...');
        $.get('/authedApi')
            .done(function(res) {
                console.log('request succeeded. Response:', res);
            })
            .fail(function(res) {
                console.log('request failed. Response:', res);
            });
    });
});