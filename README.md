
# Item-Catalog
##### Udacity Full Stack Nanodegree forth project
catalog web app where users can add, edit, and delete items and authenticate with google account.
## Setup and run the project
### Prerequisites
* Python 3.7
* Vagrant
* VirtualBox

### How to Run
1. Install VirtualBox and Vagrant
2. Clone this repo
3. Unzip and place the Item Catalog folder in your Vagrant directory
4. Launch Vagrant
```
$ Vagrant up 
```
5. Login to Vagrant
```
$ Vagrant ssh
```
6. Change directory to `/vagrant`
```
$ Cd /vagrant
```
7. Launch application
```
$ Python app.py
```
8. Open the browser and go to http://localhost:5000

### JSON endpoints
#### Returns JSON of specific  item

```
/<int:category_id>/<int:item_id>/JSON
```
#### Returns JSON of category

```
/<int:category_id>/JSON
```
