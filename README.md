Multiuser Blog Website

1.	Description: This blog website is hosting on Google Cloud Server.
	The purpose of this website is allow user to post, comment,
	and like the blog that user has posted.

2. Features:
	- Users: the website allow the visitors to create user.
				User for the website is a requirement for posting,
				comment, and like the post that user has posted.

	- Post: the registered users can create, edit, or delete posts, 
			or like other users' posts.

3. Technology:
	This website is using Google App Engine for Python, jinja template, 
	and bootstrap template.

4. Structure of the files:
	The files structure are seperated by root folder, img, static, 
	and template folder.

	- Root folder has the following file:
		+ readme.txt: this file.
		+ app.yaml: is the application configuration file for the website
		+ index.yaml: is configuration of the datastore of the website
					database.
		+ blog.py: is the backend python file to process all the website
					process such as handle request, render file template,
					doing calculation, and response to the font-end requests.

	- img: is the folder use to store image. It has the following file:
		+ cover-photo.png: is the cover photo on the top of the website

	- static: folder to store some static file such as bootstrap, and css files
			template. This folder has the following files:
		+ bootstrap*.css: these files are bootstrap template files.
		+ main.css: is the css file use to style the website pages.

	- templates: this folder uses to store all the html template files for 
		rendering the website. It has the following files:
		+ base.html: this file is use to template the header and footer of the
				the website. It set style for the whole website.
		+ editpost.html: this is the template when the user call to edit the 
				post.
		+ front.html: use to display all the post when users visits the front page.
		+ login-form.html: is the login page.
		+ newpost.html: display when the user want to create a new post.
		+ permalink.html: display a single detail of the post and also display the 
				comments for the post.
		+ signup-form.html: is the signup form for registering new user for the website.
		+ single_post.html: render the post while permalink.html is call.
5. Hosting:
	The url to host this website is: http://multiblog-001.appspot.com/

6. Deploy and Update the website:

	To deploy the website there will be the following requrements:
		- Google account with the google app engine project must be 
			created on the account. 
		- Local computer with Python and Google Cloud SDK (Python version) installed.

	To deploy the app to google cloud use the following command:

		- gcloud app deploy --project multiblog-001 -v 1
		
			where:	+ [multiblog-001] is the project-id which was gotten from
						google cloud console.
					+ 1 is the version number.

		- appcfg.py update_indexes C:\MultiUserBlog\MultiUserBlog -A multiblog-001 -V 1
			This command use to update the index file on the google datastore so that the
			database query will work. If the index file on the datastore are not created or
			updated there will be an error throw while the database query being call.

					+ [C:\MultiUserBlog\MultiUserBlog] is the path to the project
					+ [multiblog-001] is the project-id which was gotten from
						google cloud console.

	To update the website uses the following command:

		- appcfg.py update -A multiblog-001 -v 1

		where:	+ [multiblog-001] is the project-id which was gotten from
						google cloud console.
				+ 1 is the version number.

7. Credit: 
	- Some code use in this website are obtained from Udacity.com
	- bootstrap template.
