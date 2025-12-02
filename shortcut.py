import os
import pathlib
import subprocess


def clear_screen():
    os.system("clear")


def show_cmd():
    # display the current working directory 
    cmd = os.getcwd()
    print(f"Curent working directory: {cwd}\n")

def get_desktop_path():
    #return the path to the user's desktop
    return pathlib.Path.home() / "Desktop"


# Creating the Symbolic Link

def create_symbolic_link():
    # ask the user for the full filepath
    target = input("Enter the full path of the file you want to create a shortcut for: ")
    target_path = pathlib.path(target)

    #verify if the file exists
    if not target_path.exists():
        print("The full path does not exist.")
        return # returns None

    # user desktop path
    desktop_path = get_desktop_path()
    link_name = target_path.name
    link_path = desktop_path / link_name

    if link_path.exists():
        choice = input(f"A file or link named '{link_name}' already exists on your Desktop. Overwrite it? (y/n): ").lower()
        if choice != 'y':
            print("Operation canceled.")
            return
        link_path.unlink()


    try:
        os.symlink(target_path, linkpath)
        print(f"Symbolic link created on Desktop: {link_path}")
    except PermissionError:
        print("Error: Permission denied. Try running the elevated priviledges.")
    except Exception as e:
        print(f"Error creating symbolic link: {e}")


# Delete the symbolic link

def delete_symbolic_link():
    desktop_path = os.path.expanduser("~/Desktop")
    link_name = input("Enter the name of the symbolic link to delete (as it appears on the Desktop): ").strip()
    link_path = os.path.join(desktop_path, link_name)

    if not os.path.exists(link_path):
        print("Error: That file or link does not exist on your Desktop.")
        return
    if not os.path.islink(link_path):
        print("Error: That is not a symbolic link.")
        return

    try: 
        os.remove(link_path)
        print(f"Symbolic link '{link_name}' deleted sucessfully.")
    except Exception as e:
        print(f"Error deleting symbolic link: {e}")

# generate symbolic link report
def generate_symbolic_link_report():
    home_dir = pathlib.Path.home()
    desktop_dir = get_desktop_path()

    print("\n--- Symbolic Link Report ---\n")
    desktop_links = []
    home_links = []

    # find symbolic links on desktop
    for item in desktop_dir.iterdir():
        if item.is_symlink():
            try:
                target = os.readlink(item)
                desktop_links.append((item.name, target))
            except OSError:
                continue
    # find all symbolic links in the user's home directory
    for path in home_dir.rglob("*"):
        if path.is_symlink():
            home_links.append(path)

    # Report symbolic links on Desktop
    if desktop_links:
        print("Symbolic Links on Desktop:\n")
        for name, target in desktop_links:
            print(f"{name} -> {target}")
    else:
        print("No symbolic links found on Desktop.")

        print(f"\nTotal symbolic links in your home directoyr: {len(home_links)}")

if __name__ == "__main__":
    # test both funcitons manually for now
    print("1. Create a symbolic link")
    print("2. Delete a symblic link")
    print("3. Generate a symbolic link report")

    choice = input("Choose an option (1/3): ").strip()

    if choice == '1':
        create_symbolic_link()
    elif choice == '2':
        delete_symbolic_link()
    elif choice == '3':
        generate_symbolic_link_report()
    else:
        print("Invalid selection")



































