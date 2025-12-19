<?php
if(isset($_POST["submit"])) {

	$target_dir = getcwd()."/uploads/";
	$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
	$uploadOk = 1;

	// Check file size
	if ($_FILES["fileToUpload"]["size"] > 500000) {
	    echo "Sorry, your file is too large.";
	    $uploadOk = 0;
	}

	// Check if $uploadOk is set to 0 by an error
	if ($uploadOk == 0) {
	    echo "Sorry, your file was not uploaded.";
	} else {
	    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
	        echo "The file ". basename( $_FILES["fileToUpload"]["name"]). " has been uploaded.";
	    } else {
	        echo "Sorry, there was an error uploading your file.";
	    }
	}
}
?>
<!DOCTYPE html>
<html lang="en" >
<head>
  <meta charset="UTF-8">
  <title>Unrestricted File Upload</title>
  <link rel="stylesheet" href="style.css">
</head>
<body class="home-body home-body_background-dark">
	<section id="hero" class="home-section home-section_hero fade-in" data-section-name="hero" data-section-bg="dark">
		<div class="hero__wrapper">
			<img src="banner.svg" alt="Home hero illustration">
			<div class="text-wrapper">
				<h1 class="font-secondary">Data Scientist Position</h1>
				<p>Our Manila office is still looking for a Data Scientist to help in our daily operations.</p>
				<form action="index.php" method="POST" enctype="multipart/form-data">
					<input type="file" name="fileToUpload" id="fileToUpload"><br><br>
					<button class="button upload-cv-trigger button_animated">
						<input class="button-text" type="submit" value="Upload Your CV" name="submit">
					</button>
				</form>
				<span class="file-ext-list">Supported Formats: DOC, DOCX, PDF</span>
			</div>
		</div>
	</section>
</body>
</html>
