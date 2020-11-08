# mypy: ignore-errors
import ast
import inspect
import io
import os
import sys
import tempfile
import warnings

import cloudpickle
import dvc.api
import git
from dvc import main


class StudyProjectPickle(cloudpickle.CloudPickler):
    def __init__(
        self,
        file,
        protocol=None,
        buffer_callback=None,
        cb_reducer_override=lambda obj, superValue: True,
    ):
        super().__init__(file, protocol, buffer_callback)
        self.cb_reducer_override = cb_reducer_override

    def reducer_override(self, obj):
        superValue = super().reducer_override(obj)
        if self.cb_reducer_override:
            self.cb_reducer_override(obj, superValue)
        return superValue


def unicodetoascii(text):

    uni2ascii = {
        ord("\xe2\x80\x99".decode("utf-8")): ord("'"),
        ord("\xe2\x80\x9c".decode("utf-8")): ord('"'),
        ord("\xe2\x80\x9d".decode("utf-8")): ord('"'),
        ord("\xe2\x80\x9e".decode("utf-8")): ord('"'),
        ord("\xe2\x80\x9f".decode("utf-8")): ord('"'),
        ord("\xc3\xa9".decode("utf-8")): ord("e"),
        ord("\xe2\x80\x9c".decode("utf-8")): ord('"'),
        ord("\xe2\x80\x93".decode("utf-8")): ord("-"),
        ord("\xe2\x80\x92".decode("utf-8")): ord("-"),
        ord("\xe2\x80\x94".decode("utf-8")): ord("-"),
        ord("\xe2\x80\x94".decode("utf-8")): ord("-"),
        ord("\xe2\x80\x98".decode("utf-8")): ord("'"),
        ord("\xe2\x80\x9b".decode("utf-8")): ord("'"),
        ord("\xe2\x80\x90".decode("utf-8")): ord("-"),
        ord("\xe2\x80\x91".decode("utf-8")): ord("-"),
        ord("\xe2\x80\xb2".decode("utf-8")): ord("'"),
        ord("\xe2\x80\xb3".decode("utf-8")): ord("'"),
        ord("\xe2\x80\xb4".decode("utf-8")): ord("'"),
        ord("\xe2\x80\xb5".decode("utf-8")): ord("'"),
        ord("\xe2\x80\xb6".decode("utf-8")): ord("'"),
        ord("\xe2\x80\xb7".decode("utf-8")): ord("'"),
        ord("\xe2\x81\xba".decode("utf-8")): ord("+"),
        ord("\xe2\x81\xbb".decode("utf-8")): ord("-"),
        ord("\xe2\x81\xbc".decode("utf-8")): ord("="),
        ord("\xe2\x81\xbd".decode("utf-8")): ord("("),
        ord("\xe2\x81\xbe".decode("utf-8")): ord(")"),
    }
    return text.decode("utf-8").translate(uni2ascii).encode("ascii")


class ImportFinder(ast.NodeVisitor):
    def __init__(self):
        self.imports = []

    def processImport(self, full_name):
        self.imports.append(full_name)

    def visit_Import(self, node):
        for alias in node.names:
            self.processImport(alias.name)

    def visit_ImportFrom(self, node):
        if node.module == "__future__":
            return

        for alias in node.names:
            name = alias.name
            fullname = f"{node.module}.{name}" if node.module else name
            self.processImport(fullname)


class Utils:
    class Pickle:
        @staticmethod
        def find_imports(text):
            root = ast.parse(text)
            visitor = ImportFinder()
            visitor.visit(root)
            return visitor.imports

        @staticmethod
        def find_imports_from_obj(obj):
            return Utils.Pickle.find_imports(inspect.getsource(obj).strip())

        @staticmethod
        def dump(
            obj,
            file,
            protocol=None,
            buffer_callback=None,
            return_modules=False,
            log=False,
        ):
            """Serialize obj as bytes streamed into file
            protocol defaults to cloudpickle.DEFAULT_PROTOCOL which is an alias to
            pickle.HIGHEST_PROTOCOL. This setting favors maximum communication
            speed between processes running the same Python version.
            Set protocol=pickle.DEFAULT_PROTOCOL instead if you need to ensure
            compatibility with older versions of Python.
            """
            modules = set()

            def cb_reducer(obj, value):
                if log:
                    print(
                        "(Utils.Pickle.dump:cb_reducer:obj,value) : ",
                        obj,
                        value,
                    )
                if hasattr(obj, "__module__"):
                    modules.add(obj.__module__)

            pickler = StudyProjectPickle(
                file,
                protocol=protocol,
                buffer_callback=buffer_callback,
                cb_reducer_override=cb_reducer if return_modules else None,
            )
            pickler.dump(obj)
            if return_modules:
                return modules

        load = cloudpickle.load
        loads = cloudpickle.loads

        @staticmethod
        def dumps(
            obj,
            protocol=None,
            buffer_callback=None,
            return_modules=False,
            log=False,
        ):
            """Serialize obj as a string of bytes allocated in memory
            protocol defaults to cloudpickle.DEFAULT_PROTOCOL which is an alias to
            pickle.HIGHEST_PROTOCOL. This setting favors maximum communication
            speed between processes running the same Python version.
            Set protocol=pickle.DEFAULT_PROTOCOL instead if you need to ensure
            compatibility with older versions of Python.
            """
            modules = list()

            def cb_reducer(obj, value):
                if log:
                    print(
                        "(Utils.Pickle.dumps:cb_reducer:obj,value) : ",
                        obj,
                        value,
                    )
                if hasattr(obj, "__module__"):
                    modules.append(obj.__module__)
                    try:
                        m = Utils.Pickle.find_imports_from_obj(obj)
                        modules.extend(list(m))
                    except Exception as e:
                        pass

            with io.BytesIO() as file:
                cp = StudyProjectPickle(
                    file,
                    protocol=protocol,
                    buffer_callback=buffer_callback,
                    cb_reducer_override=cb_reducer if return_modules else None,
                )
                cp.dump(obj)
                modules = set(modules)
                return (
                    file.getvalue()
                    if not return_modules
                    else (file.getvalue(), modules)
                )

    class RE:
        @staticmethod
        def captureValueInLine(text, pattern, sep=":"):
            import re

            return re.findall(
                f"^.*{pattern}{sep}(.+)$", text, flags=re.MULTILINE
            )[0].strip()

        @staticmethod
        def match(text, pattern):
            import re

            return re.match(pattern, text) is not None

        @staticmethod
        def findall(text, pattern, flags=None):
            import re

            return re.findall(pattern, text)

    class Hash:
        @staticmethod
        def md5(string):
            import hashlib

            return hashlib.md5(string.encode()).hexdigest()  # nosec

        @staticmethod
        def function_md5(func):
            import inspect

            return Utils.Hash.md5(inspect.getsource(func))

    class Df:
        @staticmethod
        def to_csv(df, filename, index=True):
            df.to_csv(filename, index=False)

        @staticmethod
        def to_csv_string(df, index=True):
            import io

            s = io.StringIO()
            Utils.Df.to_csv(df, s, index=index)
            return s.getvalue()

        @staticmethod
        def from_csv_string(csvString):
            import io

            import pandas as pd

            s = io.StringIO(csvString)
            return pd.read_csv(s)

    class String:
        @staticmethod
        def remove_accents(text):
            import unicodedata

            return "".join(
                c
                for c in unicodedata.normalize("NFD", text)
                if unicodedata.category(c) != "Mn"
            )

        @staticmethod
        def remove_not_alphanumeric(text):
            import re

            return re.sub("[^a-zA-Z0-9 ]", "", text)

        @staticmethod
        def parse(text, sep=":"):
            import re

            dico = {}
            if len(text) == 0:
                return dico
            for i in text.split("\n"):
                m = re.findall(f"^([^{sep}]+){sep}(.+)$", i)
                if len(m) == 0:
                    continue
                dico[m[0][0].strip()] = m[0][1].strip()
            return dico

        @staticmethod
        def unicodeToString(uni):
            return unicodetoascii(uni)

    class Shell:
        @staticmethod
        def command(commandString, shell=False):
            import shlex
            import subprocess

            # process = subprocess.Popen(
            #     shlex.split(commandString) if not shell else commandString,
            #     stdout=subprocess.PIPE,
            #     shell=shell,  # nosec
            # )
            p = subprocess.run(
                shlex.split(commandString) if not shell else commandString,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=shell,  # nosec
            )
            output, error = p.stdout, p.stderr
            error2 = (
                None
                if p.returncode == 0
                else (
                    output.decode("utf-8")
                    if (output and "error" in output.decode("utf-8").lower())
                    else error
                )
            )
            return Struct(
                **{
                    "output": output.decode("utf-8"),
                    "output_orgi": output,
                    "error": error2,
                    "errorOrig": error,
                    "commandString": commandString,
                }
            )

    class File:
        @staticmethod
        def exist(file):
            import os.path

            return os.path.isfile(file)

        @staticmethod
        def read(filename):
            with open(filename) as f:
                output = f.read()
            return output

        @staticmethod
        def write(text, filename):
            with open(filename, "w") as f:
                f.write(text)

        @staticmethod
        def tmp(ext="csv"):
            file = TMP_FILE()
            return file.get_filename(ext)

        @staticmethod
        def write_in_tmp(text, ext="csv"):
            file = TMP_FILE()
            filename = file.get_filename(ext)
            Utils.File.write(text, filename)
            return filename

        @staticmethod
        def tmp_delete(filename):
            file = TMP_FILE()
            file.filename = filename
            file.delete()

        @staticmethod
        def touch(file):
            Utils.Shell.command(f"touch '{file}'")

    class Dir:
        @staticmethod
        def mk(dir, p=None):
            os.mkdir(dir)

        @staticmethod
        def exist(dir):
            return os.path.isdir(dir)

    @staticmethod
    def ifelse(condition, true, false=""):
        return true if condition else false

    @staticmethod
    def md5FromDf(df, index=False):
        md5 = Utils.Hash.md5(Utils.Df.to_csv_string(df, index=index))
        return md5


class TMP_FILE:
    def __init__(self):
        self.filename = None

    def get_filename(self, ext="png"):
        if self.filename is not None:
            self.delete()
        _, self.filename = tempfile.mkstemp(suffix="." + ext)
        return self.filename

    def delete(self):
        # print(self.i)
        os.remove(self.filename)


class Struct(dict):
    def __init__(self, **kw):
        dict.__init__(self, kw)
        self.__dict__.update(kw)

    def __str__(self):
        a = ""
        for i in self.__dict__.keys():
            a += f"{i} :"
            a += f"\n\t{self.__dict__[i]}\n"
        return a


class Git:
    installed = False
    path = ".git"
    gitignore = ".gitignore"

    @staticmethod
    def getGit():
        return git.cmd.Git(os.getcwd())

    @staticmethod
    def commandGit(command, *args, **xargs):
        rep = Utils.Shell.command(f"git {command}", *args, **xargs)
        return rep

    @staticmethod
    def check_installed():
        return Git.installed or os.path.isdir(os.getcwd() + f"/{Git.path}")

    @staticmethod
    def install(add=True, commit=True, message="git installed", name=None):
        print("\tset up Git...")
        g = Git.getGit()
        g.init()
        if name is not None:
            Git.addBranch(name)
        Utils.Shell.command(f"touch {Git.gitignore}")
        if add:
            Git.add([Git.gitignore])
        if commit:
            StudyProjectEnv.commit(message)
        print("\tGit initialized")
        Git.installed = True

    @staticmethod
    def addTag(name, desc):
        g = Git.getGit()
        g.tag(["-a", f"'{name}'", "-m", f"'{desc}'"])

    @staticmethod
    def getRefBranches():
        rep = Git.commandGit("branch --format '%(refname)'")
        if rep.error:
            raise Exception(rep)
        return rep.output.strip()

    @staticmethod
    def getRefAndHeadBranches():
        rep = Git.commandGit("branch --format '%(refname) %(objectname)'")
        if rep.error:
            raise Exception(rep)
        return rep.output.strip()

    @staticmethod
    def reset():
        rep = Git.commandGit("reset")
        if rep.error:
            raise Exception(rep)

    @staticmethod
    def ignoreChanges(pathToIgnore=[]):
        if len(pathToIgnore) == 0:
            rep = Git.commandGit("rm --cached --ignore-unmatch *")
            if rep.error:
                raise Exception(rep)
        else:
            g = Git.getGit()
            g.rm(["--cached"] + pathToIgnore)

    @staticmethod
    def getBranches(pattern=None, withHash=False):
        if not withHash:
            refBranches = Git.getRefBranches()

            branches = [i.split("/")[2] for i in refBranches.split("\n")]
            if pattern is not None:
                return [
                    i
                    for i in branches
                    if Utils.RE.match(text=i, pattern=pattern)
                ]
            return branches
        refBranches = Utils.String.parse(Git.getRefAndHeadBranches(), sep=" ")
        branches = {
            ref.split("/")[2]: head for ref, head in refBranches.items()
        }
        if pattern is not None:
            return {
                k: v
                for k, v in branches.items()
                if Utils.RE.match(text=k, pattern=pattern)
            }
        return branches

    @staticmethod
    def getBranch():
        rep = Git.commandGit(f"branch --show-current")
        if rep.error:
            raise Exception(rep)
        return rep.output.strip()

    @staticmethod
    def deleteBranch(name, force=False):
        Git.commandGit(f"branch {Utils.ifelse(force,'-D','-d')} {name}")

    @staticmethod
    def checkBranch(name):
        rep = Git.commandGit(
            f"branch  --list '{name}' | tr -d ' '", shell=True  # nosec
        )
        if rep.error:
            raise Exception(rep)
        branch = rep.output
        return len(branch) > 0

    @staticmethod
    def addBranch(name, checkout=True, show_rep=False):
        if Git.checkBranch(name):
            return
        if checkout:
            g = Git.getGit()
            g.checkout(["-b", f"{name}"])
        else:
            g = Git.getGit()
            g.branch([f"{name}"])

    @staticmethod
    def getNoHooks():
        return " -c core.hooksPath=/dev/null "

    @staticmethod
    def getStaged():
        stagedString = Git.commandGit(
            "diff --name-only --cached"
        ).output.rstrip()
        if len(stagedString) == 0:
            return []
        return stagedString.split("\n")

    @staticmethod
    def getModified():
        stagedString = Git.commandGit("diff --name-only").output.rstrip()
        if len(stagedString) == 0:
            return []
        return stagedString.split("\n")

    @staticmethod
    def temporaryCommit():
        m = Git.getModified()
        if len(m) == 0:
            return False
        Git.reset()
        # print(Git.getBranch(),m)
        Git.ignoreChanges(m)
        # Git.add(u=True)
        staged = Git.getStaged()
        # print(staged)
        if len(staged) == 0:
            return False
        StudyProjectEnv.commit("tempCommit")
        return True

    @staticmethod
    def backCommit():
        Git.commandGit("reset --mixed HEAD^1")

    @staticmethod
    def temporaryCommitBack():
        Git.backCommit()
        # Git.reset()

    @staticmethod
    def goToBranch(name, no_hooks=False, show_rep=False, no_reset=True):
        # g = Git.getGit()
        # g.checkout([f"{name}"])

        tempCommit = Git.temporaryCommit() if not no_reset else False
        # if not no_reset:
        #     Git.reset()
        #     Git.ignoreChanges()
        hooks = Git.getNoHooks() if no_hooks else ""
        rep = Git.commandGit(f"{hooks}checkout {name}")
        if show_rep:
            print(rep)
        if rep.error:
            print(rep)
            raise Exception(rep)
        return tempCommit

    @staticmethod
    def toBrancheName(name, sep="-"):
        import re

        name = name.strip()
        name = Utils.String.remove_accents(name)
        name = Utils.String.remove_not_alphanumeric(name)
        name = re.sub(" +", " ", name)
        name = re.sub(" ", sep, name)
        name = name.lower()
        return name

    @staticmethod
    def getConfigUser(author):
        return " ".join(
            [
                "-c",
                f"user.name='{author.split('<')[0].strip()}'",
                "-c",
                f"user.email='{author.split('<')[1][:-1].strip()}'",
            ]
        )

    @staticmethod
    def commit(message, author=""):
        if len(author) > 0:
            commiter = Git.getConfigUser(author)
            author = f'--author="{author}"'
            message = message.replace("'", '"')
            rep = Git.commandGit(f"{commiter} commit {author} -m '{message}'")
            if rep.error:
                print(rep)
                raise Exception(rep.error)
            # if rep.output:
            #   print(rep.output,rep.commandString)
            return
        g = Git.getGit()
        if author:
            g.commit([author, "-m", f"'{message}'"])
        else:
            g.commit(["-m", f"'{message}'"])

    @staticmethod
    def merge(branch, no_ff=True, message="", author=""):
        if len(author) > 0:
            commiter = Git.getConfigUser(author)
            message = message.replace("'", '"')
            messageN = f"-m '{message}'"
            rep = Git.commandGit(
                f"{commiter} merge {Utils.ifelse(no_ff,'--no-ff')} {Utils.ifelse(message,messageN)} {branch}"
            )
            if rep.error:
                print(rep)
                raise Exception(rep.error)
            # if rep.output:
            #   print(rep.output, rep.commandString)
            return
        g = Git.getGit()
        g.merge([Utils.ifelse(no_ff, "--no-ff"), branch])

    @staticmethod
    def add(listToAdd=[], u=False):

        g = Git.getGit()
        if u:
            g.add("-u", [] + listToAdd)
        else:
            g.add([] + listToAdd)

    @staticmethod
    def checkIdentity():
        rep = Git.config("user.name", globally=True)
        if rep.error:
            raise Exception(rep.error)
        rep2 = Git.config("user.name", globally=False)
        if rep2.error:
            raise Exception(rep2.error)
        return len(rep.output) > 0 or len(rep2.output) > 0

    @staticmethod
    def config(k, v=None, globally=False, remove=False):
        return Git.commandGit(
            f"config {Utils.ifelse(globally,'--global')} {Utils.ifelse(v is None and not remove,'--get')} {Utils.ifelse(remove,'--unset')} {k} {Utils.ifelse(v is not None, v)}"
        )


class Dvc:
    path = ".dvc"
    installed = False
    dvcignore = ".dvcignore"
    author = "DvcBot <DvcBot@DvcBot.DvcBot>"
    textCheckDocker = """
check_docker_container(){
    container="${1}"
    lignes=$(docker ps -a --filter "name=^${container}$" | wc -l | tr -d ' ')
    [ "$lignes" -gt 1 ]
    return $?
}
if [ -z "$DOCKER_CONTAINER_NAME" ]; then
    if ! command -v dvc &> /dev/null
    then
        if ! command -v docker &> /dev/null
        then
            exit
        else
            if [ -f ".study-project-init" ]; then
                DOCKER_CONTAINER_NAME=$(cat ".study-project-init")
                if check_docker_container "$DOCKER_CONTAINER_NAME"
                then
                    alias exec="docker exec -d "$DOCKER_CONTAINER_NAME""
                fi
            fi
        fi
    fi
fi
"""

    @staticmethod
    def check_installed():
        return Dvc.installed or os.path.isdir(os.getcwd() + f"/{Dvc.path}")

    @staticmethod
    def changeHookDVC(name):
        fileLines = Utils.File.read(f"{Git.path}/hooks/{name}").split("\n")
        newLines = (
            fileLines[:1] + Dvc.textCheckDocker.split("\n") + fileLines[1:]
        )
        Utils.File.write("\n".join(newLines), f"{Git.path}/hooks/{name}")

    @staticmethod
    def changeHooksDVC():
        for i in ["pre-commit", "pre-push", "post-checkout"]:
            Dvc.changeHookDVC(i)

    @staticmethod
    def install():
        print("\tset up dvc...")
        k = main.main(["init", "--quiet"])
        Dvc.config("core.autostage", "true")
        Git.add([f"{Dvc.path}/config"])
        main.main(["install"])
        Dvc.changeHooksDVC()
        StudyProjectEnv.commit("dvc installed (config+hooks)")
        print("\tDvc initialized")
        Dvc.installed = True

    @staticmethod
    def commit(message, author=None):
        author = Dvc.author if author is None else author
        return Git.commit(message, author=Dvc.author)

    @staticmethod
    def merge(branch, no_ff=True, message="", author=None):
        author = Dvc.author if author is None else author
        return Git.merge(branch, no_ff=no_ff, author=author, message=message)

    @staticmethod
    def config(k, v):
        main.main(["config", k, v])

    @staticmethod
    def addDataFromDF(df, name, path="", to="csv", ext="csv", index=False):
        file = TMP_FILE()
        if to not in ["csv"]:
            print(f"to:'{to}' not implemented")
            return
        if len(path) > 0:
            path = path + "/"
        df.to_csv(f"{path}{name}.{ext}", index=index)
        main.main(
            [
                "add",
                f"{path}{name}.{ext}",
            ]
        )

    @staticmethod
    def getMd5(filename, path="", ext="csv"):
        if len(path) > 0:
            path = path + "/"
        if not Utils.File.exist(f"{path}{filename}.{ext}.dvc"):
            return None
        file = Utils.File.read(f"{path}{filename}.{ext}.dvc")
        return Utils.RE.captureValueInLine(file, "md5")

    @staticmethod
    def open(fileName):
        with dvc.api.open(fileName) as fd:
            text = fd.read()
        return text

    @staticmethod
    def read(fileName):
        return dvc.api.read(fileName)


class StudyProjectEnv:
    prefix_branch = "study_project"
    master = f"{prefix_branch}/study_project"
    nb = "master"
    installed = False
    path_docker_init = ".study-project-init"
    path = ".study_project"
    study_project_config = ".config"
    step = 0
    prefixe = "study_project : "
    default_branch = "study_project_set_up"
    data_path = "data"
    study_project_data = "data"
    study_project_projects = "projects"
    study_project_studies = "studies"
    # proj
    projSetUp = "setup"
    projData = "data"
    project_prefixe = "project"
    gitIgnore = f"""

{path_docker_init}
__pycache__/
.ipynb_checkpoints/
{Git.gitignore}.*
{data_path}/*

"""
    gitIgnoreBranch = f"""
*
!/{path}/
!/{path}/*
!/{Dvc.path}/
!/{Dvc.path}/*
!/{data_path}/
!/{data_path}/
!{Git.gitignore}
!{Dvc.dvcignore}

"""
    # TODO: alias git when destination path change per_exemple()
    postCheckoutGitignoreCheck = f"""

old_ref=$1
new_ref=$2
branch_switched=$3

if [ $branch_switched != '1' ]
then
    echo "---- NO CHECKOUT ----"
    exit 0
fi
echo "---- POST CHECKOUT ----"
current_branch=$(git rev-parse --abbrev-ref HEAD | tr '/' '_')
hook_dir=$(dirname $0)
root_dir="$(pwd -P)"
info_dir="$root_dir/{Git.path}/info"

exclude_target='{Git.gitignore}'
if [ -f "$root_dir/$exclude_target.$current_branch" ]
then
    echo "Prepare to use {Git.gitignore}.$current_branch as exclude file"
    exclude_target={Git.gitignore}.$current_branch
fi
cd "$info_dir"
rm exclude
echo "Copy {Git.gitignore}.$current_branch file in place of exclude"
cp "$root_dir/$exclude_target" exclude
echo "--- POST CHECKOUT END ---"
cd "$root_dir"

"""

    @staticmethod
    def addGitIgnore():
        Utils.File.write(f"{StudyProjectEnv.gitIgnore}", Git.gitignore)

    @staticmethod
    def addGitIgnoreBranch(branchName):
        branchName = branchName.replace("/", "_")
        Utils.File.write(
            StudyProjectEnv.gitIgnoreBranch, f"{Git.gitignore}.{branchName}"
        )

    @staticmethod
    def addPostCheckoutHook():
        name = "post-checkout"
        fileLines = Utils.File.read(f"{Git.path}/hooks/{name}").split("\n")
        newLines = (
            fileLines[:1]
            + StudyProjectEnv.postCheckoutGitignoreCheck.split("\n")
            + fileLines[1:]
        )
        Utils.File.write("\n".join(newLines), f"{Git.path}/hooks/{name}")

    @staticmethod
    def addPreCommitHook():
        name = "pre-commit"
        fileLines = Utils.File.read(f"{Git.path}/hooks/{name}").split("\n")
        newLines = (
            fileLines[:1]
            + StudyProjectEnv.textPreCommit.split("\n")
            + fileLines[1:]
        )
        Utils.File.write("\n".join(newLines), f"{Git.path}/hooks/{name}")

    @staticmethod
    def add():
        Git.add([StudyProjectEnv.path + "/", Git.gitignore])

    @staticmethod
    def check_installed():
        return StudyProjectEnv.installed or os.path.isdir(
            os.getcwd() + "/" + StudyProjectEnv.path
        )

    @staticmethod
    def install():
        print("\tset up study_project...")
        os.mkdir(StudyProjectEnv.path)
        StudyProjectEnv.addGitIgnore()
        os.mkdir(StudyProjectEnv.data_path)
        Utils.File.touch(StudyProjectEnv.data_path + f"/{Git.gitignore}")
        os.mkdir(
            StudyProjectEnv.path + f"/{StudyProjectEnv.study_project_projects}"
        )
        os.mkdir(
            StudyProjectEnv.path + f"/{StudyProjectEnv.study_project_config}"
        )
        Utils.File.touch(
            StudyProjectEnv.path
            + f"/{StudyProjectEnv.study_project_projects}"
            + f"/{Git.gitignore}"
        )
        os.mkdir(
            StudyProjectEnv.path + f"/{StudyProjectEnv.study_project_studies}"
        )
        Utils.File.touch(
            StudyProjectEnv.path
            + f"/{StudyProjectEnv.study_project_studies}"
            + f"/{Git.gitignore}"
        )
        os.mkdir(
            StudyProjectEnv.path + f"/{StudyProjectEnv.study_project_data}"
        )
        Utils.File.touch(
            StudyProjectEnv.path
            + f"/{StudyProjectEnv.study_project_data}"
            + f"/{Git.gitignore}"
        )
        Utils.File.write(
            f"\n{StudyProjectEnv.study_project_config}\n"
            + StudyProjectEnv.gitIgnore,
            f"{StudyProjectEnv.path}/{Git.gitignore}",
        )

        StudyProjectEnv.addPostCheckoutHook()
        print("\tstudy_project initialized")
        StudyProjectEnv.installed = True
        Git.add(
            [
                StudyProjectEnv.path,
                StudyProjectEnv.path + "/",
                StudyProjectEnv.data_path,
                # StudyProjectEnv.data_path + "/",
                Git.gitignore,
            ]
        )
        StudyProjectEnv.commit("study_project installed")

    @staticmethod
    def addBranch(name, *args, **xargs):
        brName = f"{StudyProjectEnv.step}-{name}"
        Git.addBranch(brName, *args, **xargs)
        StudyProjectEnv.step += 1
        return brName

    @staticmethod
    def getProjectVersions(id):
        projName = StudyProjectEnv.getProjectBranchName(id, no_prefix=True)
        # StudyProjectEnv.getConfigProject(id)
        if Utils.File.exist(
            f"{StudyProjectEnv.path}/{StudyProjectEnv.study_project_config}/{projName}"
        ):
            return Utils.File.read(
                f"{StudyProjectEnv.path}/{StudyProjectEnv.study_project_config}/{projName}"
            )
        return ""

    @staticmethod
    def saveProjectVersions(id, versions):
        projName = StudyProjectEnv.getProjectBranchName(id, no_prefix=True)
        if not Utils.Dir.exist(
            f"{StudyProjectEnv.path}/{StudyProjectEnv.study_project_config}"
        ):
            Utils.Dir.mk(
                f"{StudyProjectEnv.path}/{StudyProjectEnv.study_project_config}"
            )
        Utils.File.write(
            versions,
            filename=f"{StudyProjectEnv.path}/{StudyProjectEnv.study_project_config}/{projName}",
        )
        return versions

    @staticmethod
    def getVersions(id):
        # projName = StudyProjectEnv.getProjectBranchName(id)
        return StudyProjectEnv.getProjectVersions(id)

    @staticmethod
    def getVersion(hash, id):
        versionsDict = StudyProjectEnv.getVersionsDict(id)
        return versionsDict[hash] if hash in versionsDict else None

    @staticmethod
    def getHashFromVersion(version, id):
        versionsDict = StudyProjectEnv.getVersionsDict(id)
        return versionsDict[version] if version in versionsDict else None

    @staticmethod
    def saveVersions(id, versions):
        return StudyProjectEnv.saveProjectVersions(id, versions)

    @staticmethod
    def getVersionsDict(id):
        versions = Utils.String.parse(StudyProjectEnv.getVersions(id))
        return versions

    @staticmethod
    def getVersionNumber(id):
        versions = StudyProjectEnv.getVersionsDict(id)
        return len(versions) // 2

    @staticmethod
    def addVersion(v, hash, id):
        versions = StudyProjectEnv.getVersions(id)
        versionsDict = Utils.String.parse(versions)
        last = f"{versions}\n" if len(versions) > 0 else ""
        StudyProjectEnv.saveVersions(id, f"{last}{hash}: {v}\n{v}: {hash}")

    @staticmethod
    def addProjectBranch(id):
        nb = StudyProjectEnv.getVersionNumber(id)
        brName = StudyProjectEnv.getProjectBranchName(id, nb)
        Git.addBranch(brName, checkout=False)
        tempCommit = Git.goToBranch(brName, no_reset=False)
        StudyProjectEnv.addGitIgnoreBranch(brName)
        return (brName, nb, tempCommit)

    @staticmethod
    def check_all_installed():
        install = False
        if (
            not Git.check_installed()
            or not Dvc.check_installed()
            or not StudyProjectEnv.check_installed()
        ):
            if (
                Git.check_installed()
                or Dvc.check_installed()
                or StudyProjectEnv.check_installed()
            ):
                print(
                    "study_project : git/Dvc/study_project are already installed, we can't for the moment install only on off them"
                )
                # StudyProjectEnv.check_config()
                return False
            install = True
            print("Set Up Study Project ....")
            if not Git.check_installed():
                # StudyProjectEnv.check_init()
                Git.install(name=StudyProjectEnv.master)
                StudyProjectEnv.addBranch(f"set-up")
                # Git.checkout("master")
                # Git.merge("install-git")
            if not Dvc.check_installed():
                # StudyProjectEnv.addBranch(f"install-dvc")
                Dvc.install()
            if not StudyProjectEnv.check_installed():
                # StudyProjectEnv.addBranch(f"install-study-project")
                StudyProjectEnv.install()
                currBranche = Git.getBranch()
                # print("isntall").
                Git.goToBranch(StudyProjectEnv.master, no_hooks=True)
                StudyProjectEnv.merge(currBranche, message="set-up")
                Git.deleteBranch(currBranche)

                # add nb branch
                Git.addBranch(StudyProjectEnv.nb)
            print("Study Project OK")
            # return True
        StudyProjectEnv.check_config()
        return True

    @staticmethod
    def find_projects():
        from collections import defaultdict

        branches = Git.getBranches(
            pattern=f"^{StudyProjectEnv.project_prefixe}-.+"
        )
        proj = defaultdict(list)
        for i in branches:
            projName = Utils.RE.findall(
                text=i, pattern=f"^{StudyProjectEnv.project_prefixe}-(.+)-v.+$"
            )[0]
            proj[projName].append(i)

        for projName, branch in proj.items():
            projList = []
            for i in branch:
                StudyProjectEnv.goToBranch(i)

                projList.append()

        return proj

    @staticmethod
    def check_config():
        if not Utils.Dir.exist(
            f"{StudyProjectEnv.path}/{StudyProjectEnv.study_project_config}"
        ):
            Utils.Dir.mk(
                StudyProjectEnv.path
                + f"/{StudyProjectEnv.study_project_config}"
            )
            Utils.File.write(
                f"{StudyProjectEnv.study_project_config}",
                f"{StudyProjectEnv.path}/{Git.gitignore}",
            )
            StudyProjectEnv.find_projects()
        # print("OK")

    @staticmethod
    def check_init():
        rep = Git.commandGit("branch")
        if rep.error:
            raise Exception(rep.error)
        if len(rep.output) == 0:
            Utils.Shell.command("touch .initial_commit")
            Git.add([".initial_commit"])
            Git.commit()

    @staticmethod
    def goToBranch(*args, **xargs):
        return Git.goToBranch(*args, **xargs)

    @staticmethod
    def commit(message, prefixe=None):
        prefixe = StudyProjectEnv.prefixe if prefixe is None else prefixe
        return Dvc.commit(f"{prefixe}{message}")

    @staticmethod
    def merge(*args, message="", prefixe=None, **xargs):
        prefixe = StudyProjectEnv.prefixe if prefixe is None else prefixe
        message = message if len(message) == 0 else f"{prefixe}{message}"
        return Dvc.merge(*args, message=message, **xargs)

    @staticmethod
    def addData(data, filename, path=None):
        path = StudyProjectEnv.data_path if path is None else path
        md5OfData = Utils.md5FromDf(data)
        md5InFileName = Dvc.getMd5(filename, path)
        if md5InFileName != md5OfData:
            Dvc.addDataFromDF(data, filename, path=path)
            return (True, md5OfData)
        return (False, md5OfData)

    @staticmethod
    def getFileData(dataParsed, data_name, id):
        fileName = Git.toBrancheName(id, sep="_")
        path = f"{StudyProjectEnv.data_path}/{fileName}_{data_name}.csv"
        pathDvc = f"{path}.dvc"
        return Utils.Df.from_csv_string(Dvc.read(path))
        if Utils.File.exist(pathDvc):  # save fileName in data
            dataFile = Utils.File.read(pathDvc)
            md5File = Utils.RE.captureValueInLine(dataFile, "md5")
            pathFile = Utils.RE.captureValueInLine(dataFile, "path")
            if dataParsed[data_name] == md5File:
                fileData = Dvc.read(pathFile)
                return Utils.Df.from_csv_string(fileData)

    @staticmethod
    def getData(*args, **xargs):
        return Data.getData(*args, **xargs)

    @staticmethod
    def saveData(*args, **xargs):
        Data.saveData(*args, **xargs)

    @staticmethod
    def forgotData(dataHash):
        pass

    @staticmethod
    def getProjPath(id):
        return (
            StudyProjectEnv.path
            + f"/{StudyProjectEnv.study_project_projects}/"
            + Git.toBrancheName(id, sep="_")
        )

    @staticmethod
    def saveProject(project):
        def addCommit():
            StudyProjectEnv.add()
            StudyProjectEnv.commit(f"save Project '{project.id}'")

        def upVersion(dataHash, setUpMd5Proj):
            StudyProjectEnv.addVersion(
                project.v,
                Utils.Hash.md5(f"{dataHash}\n{setUpMd5Proj}"),
                project.id,
            )

        projPath = StudyProjectEnv.getProjPath(project.id)

        if not Utils.Dir.exist(projPath):
            Utils.Dir.mk(projPath)

        # os.mkdir(StudyProjectEnv.path+"/project/"+Git.toBrancheName(project.id,sep="_")+"/studies")
        # os.mkdir(StudyProjectEnv.path+"/project/"+Git.toBrancheName(project.id,sep="_")+"/data")

        dataHash = {data.get_hash(): data.id for data in project.data.values()}
        dataHash = dict(sorted(dataHash.items(), key=lambda a: a[0]))
        dataHashDico = dataHash

        dataHashStr = "\n".join(dataHash.keys())
        if not Utils.File.exist(f"{projPath}/{StudyProjectEnv.projData}"):
            lastDataHashStr = ""
        else:
            lastDataHashStr = Utils.File.read(
                f"{projPath}/{StudyProjectEnv.projData}"
            )

        if lastDataHashStr != dataHashStr:
            Utils.File.write(
                dataHashStr, filename=f"{projPath}/{StudyProjectEnv.projData}"
            )
            lastDataHash = set(lastDataHashStr.split("\n"))
            dataHash = set(dataHash.keys())
            newData = dataHash - lastDataHash
            pastData = lastDataHash - dataHash
            for i in newData:
                StudyProjectEnv.saveData(project.data[dataHashDico[i]], i)
            for i in pastData:
                StudyProjectEnv.forgotData(i)

        if project.setUp:
            setUpMd5Proj = Utils.Hash.function_md5(project.setUp)
            if Utils.File.exist(f"{projPath}/{StudyProjectEnv.projSetUp}"):
                setUpMd5 = Utils.File.read(
                    f"{projPath}/{StudyProjectEnv.projSetUp}"
                )
                if setUpMd5Proj == setUpMd5:
                    # upVersion("", setUpMd5Proj)
                    return
            Utils.File.write(
                setUpMd5Proj, filename=f"{projPath}/{StudyProjectEnv.projSetUp}"
            )

        addCommit()

        upVersion("", setUpMd5Proj)

    @staticmethod
    def getProjectBranchName(id, v=None, no_prefix=False):
        versions = "" if v is None else f"-v{v}"
        prefix = f"{StudyProjectEnv.prefix_branch}/" if not no_prefix else ""
        return f"{prefix}{StudyProjectEnv.project_prefixe}-{Git.toBrancheName(id)}{versions}"

    @staticmethod
    def getProjectBranch(id, setUp=None, version=None):
        import warnings

        def getProjHash():
            setUpMd5Proj = Utils.Hash.function_md5(setUp)
            return Utils.Hash.md5(f"\n{setUpMd5Proj}")

        branchName = StudyProjectEnv.getProjectBranchName(id, v=version)
        if setUp is None and version is None:
            vNum = StudyProjectEnv.getVersionNumber(id)
            if vNum == 0:
                return None
            version = vNum - 1
        branchName = StudyProjectEnv.getProjectBranchName(id, v=version)

        if version is not None:
            if Git.checkBranch(branchName):
                if setUp is None:
                    return branchName
                else:
                    projHash = getProjHash()
                    hashInConfig = StudyProjectEnv.getHashFromVersion(
                        version, id
                    )
                    if projHash != hashInConfig:
                        warnings.warn(
                            "/!\\ setUp different de celui en memoire : Vous devez créer une nouvelle version du project"
                        )
                        return None
                    return branchName
        projHash = getProjHash()
        v = StudyProjectEnv.getVersion(projHash, id)
        return branchName + f"-v{v}" if v is not None else None
        # studiesHash=[study.get_hash() for study in project.studies.values()]
        # Utils.File.write("\n".join(dataHash),filename=f"{projPath}/studies")

        # hash([project.data,project.studies])
        # StudyProjectEnv.create_project()

    @staticmethod
    def getProject(id, setUp):
        projPath = StudyProjectEnv.getProjPath(id)

        projStr = ""
        if Utils.Dir.exist(projPath):
            proj = StudyProject(id)
            setUpMd5Proj = None
            if Utils.File.exist(f"{projPath}/{StudyProjectEnv.projSetUp}"):
                setUpMd5 = Utils.File.read(
                    f"{projPath}/{StudyProjectEnv.projSetUp}"
                )
                if setUp is None:
                    setUpMd5Proj = setUpMd5
                    # TODO: retrieve setUp source code
                    proj.setUp = None
                else:
                    setUpMd5Proj = Utils.Hash.function_md5(setUp)
                    if setUpMd5Proj == setUpMd5:
                        proj.setUp = setUp
                    else:
                        proj.setUp = "outdated"
                        print("SetUp is not the saved")
                        return proj
                # projStr+="\n"+setUpMd5

            if Utils.File.exist(f"{projPath}/{StudyProjectEnv.projData}"):
                DataHash = Utils.File.read(
                    f"{projPath}/{StudyProjectEnv.projData}"
                )
                data = {
                    i.id: i
                    for i in [
                        StudyProjectEnv.getData(Datahashi)
                        for Datahashi in DataHash.split("\n")
                    ]
                }
                proj.data = Struct(**data)
            projHash = Utils.Hash.md5(f"\n{setUpMd5Proj}")
            proj.v = StudyProjectEnv.getVersion(projHash, proj.id)
            return proj
        return None


class Data:
    @staticmethod
    def getTrainName(fileName):
        return f"{fileName}_train"

    @staticmethod
    def getTestName(fileName):
        return f"{fileName}_test"

    @staticmethod
    def getDataName(fileName, k):
        return f"{fileName}_data_{k}"

    @staticmethod
    def getData(dataHash):
        projPath = (
            StudyProjectEnv.path + f"/{StudyProjectEnv.study_project_data}"
        )
        if Utils.File.exist(projPath + "/" + dataHash):
            dataString = Utils.File.read(projPath + "/" + dataHash)
            dataParsed2 = Utils.String.parse(
                dataString, sep=":"
            )  # {i: Utils.String.parse(dataString,sep=":") for i in ["id","comment","train","test","target"]}
            data = {}
            dataParsed = {}
            for k, v in dataParsed2.items():
                if Utils.RE.match(k, "^data."):
                    data[k[len("data.") :]] = StudyProjectEnv.getFileData(
                        {"data_" + k[len("data.") :]: v},
                        "data_" + k[len("data.") :],
                        dataParsed["id"],
                    )
                else:
                    dataParsed[k] = v
            dataParsed["data"] = data
            dataFiles = {
                i: StudyProjectEnv.getFileData(dataParsed, i, dataParsed["id"])
                for i in ["train", "test"]
            }
            dataReady = {**dataParsed, **dataFiles}
            return Data().setData(**dataReady)
        print(f"error : {projPath}   /   {dataHash}")
        return Data()

    @staticmethod
    def saveData(data, dataHash):
        projPath = StudyProjectEnv.path + "/data"
        if not Utils.File.exist(projPath + "/" + dataHash):
            StudyProjectEnv.addData(
                data.train, Data.getTrainName(data.fileName)
            )
            StudyProjectEnv.addData(data.test, Data.getTestName(data.fileName))
            fileStr = Data.get_file_export(
                data,
                lambda name, data_: StudyProjectEnv.addData(
                    data_, Data.getDataName(data.fileName, name)
                ),
            )
            Utils.File.write(fileStr, projPath + "/" + dataHash)

    def setData(self, /, id, train, test, target, comment="", data={}):
        # check is pandas df, series
        self.id = id
        self.train = train
        self.test = test
        self.target = target
        self.comment = comment
        self.data = data

        # maybe -> StudyProjectEnv should do that
        brName = Git.toBrancheName(id)
        self.fileName = Git.toBrancheName(id, sep="_")
        fileName = self.fileName
        (new, md5_train) = StudyProjectEnv.addData(
            self.train, Data.getTrainName(fileName)
        )
        # (new2, md5_target) = StudyProjectEnv.addData(
        #     self.target, f"{fileName}_target"
        # )
        (new2, md5_test) = StudyProjectEnv.addData(
            self.test, Data.getTestName(fileName)
        )
        new3 = False
        data_md5 = {}
        for k, v in self.data.items():
            (new_, md5_data_) = StudyProjectEnv.addData(
                v, Data.getDataName(fileName, k)
            )
            data_md5[k] = md5_data_
            new3 = new3 or new_
        self.data_md5 = data_md5
        self.md5_train = md5_train
        self.md5_test = md5_test
        if new or new2 or new3:
            StudyProjectEnv.commit(f"add Data '{id}'")
        # StudyProjectEnv.addBranch(f"add-data-{brName}")
        return self

    @staticmethod
    def get_file_export(data, data_data_cb=lambda name, data_: True):
        comment = data.comment.replace("\n", "\\n")
        fileStr = f"""id: {data.id}
comment: {comment}
target: {data.target}
train: {data.md5_train}
test: {data.md5_test}"""
        for name, data_ in data.data.items():
            data_data_cb(name, data_)
            fileStr += f"\ndata.{name}: {data.data_md5[name]}"
        return fileStr

    def get_hash(self):
        fileStr = Data.get_file_export(self)
        return Utils.Hash.md5(fileStr)


class Study:
    """docstring for Study"""

    def __init__(self, id, data=None):
        self.id = id
        self.data = data


class StudyProject:
    env = StudyProjectEnv
    dvc = Dvc
    git = Git
    utils = Utils

    def __init__(self, id, saveProject=True):
        self.data = {}
        self.studies = {}
        self.id = id
        self.saveProject = saveProject

    def saveData(self, id, train, test, target, comment="", data={}):
        if id in self.data:
            print(f"\tData '{id}' : loaded ")
            return self.data[id]
        print(f"\tData '{id}' : creating... ")
        dataObj = Data()
        dataObj.setData(id, train, test, target, comment, data)
        self.data[id] = dataObj
        self.data = Struct(**self.data)
        print(f"\tData '{id}' : ok ")

        if self.saveProject:
            StudyProjectEnv.saveProject(self)

    @classmethod
    def getOrCreate(self, id, setUp=None, version=None, recreate=False):
        if not StudyProjectEnv.check_all_installed():
            return

        # GOTO BRANCH MASTER:
        tempCommitBranchCurr = None
        branchCurr = Git.getBranch()
        if branchCurr != StudyProjectEnv.master:
            # TODO: check if the branche is study-project and force to be in master if it
            # print(f"getOrCreate {branchCurr}")
            tempCommitBranchCurr = Git.goToBranch(
                StudyProjectEnv.master, no_reset=False
            )
            if tempCommitBranchCurr:
                warnings.warn(
                    f"Ton travail a été commit dans un commit temporaire sur la branche {branchCurr}"
                )
            if Utils.RE.match(
                pattern=f"^{StudyProjectEnv.prefix_branch}/", text=branchCurr
            ):
                branchCurr = StudyProjectEnv.nb
                tempCommitBranchCurr = False
        else:
            branchCurr = StudyProjectEnv.nb
            tempCommitBranchCurr = False

        def comeBackMaster(tempCommit):
            # print("comeBackMaster")
            tempCommitToMaster = Git.goToBranch(
                StudyProjectEnv.master, no_reset=False
            )
            if tempCommitToMaster:
                warnings.warn(
                    f"Wtf pb il y a eu un commit temporaire : '{Git.getBranch()}' [{tempCommit}] -> '{StudyProjectEnv.master}'? "
                )
                sys.exit()
            if tempCommit:
                Git.backCommit()

        def comeBackBranchCurr():
            # print("comeBackBranchCurr", Git.getBranch(),
            # branchCur:r, tempCommitBranchCurr)
            if Git.getBranch() == branchCurr:
                return
            tempCommitToBranchCurr = Git.goToBranch(branchCurr, no_reset=False)
            if tempCommitToBranchCurr:
                warnings.warn(
                    f"Wtf pb il y a eu un commit temporaire : '{Git.getBranch()}' -> '{branchCurr}'? "
                )
                sys.exit()
            if tempCommitBranchCurr:
                Git.backCommit()
                # tempCommitBranchCurr=False

        def create_project():
            if setUp is None:
                print("setUp must me set when create project")
                comeBackBranchCurr()
                return
            if Git.getBranch() != StudyProjectEnv.master:
                warnings.warn(f"Wtf tu fou quoi ici : '{branchCurr}' ? ")
                sys.exit()
                # Git.goToBranch(StudyProjectEnv.master)
            (brName, v, tempCommit) = StudyProjectEnv.addProjectBranch(id)
            df = " " * len(f"Project '{id}' ")
            print(f"Project '{id}' (v{v}) : creating...")
            proj = self(id)
            proj.setUp = setUp
            proj.v = v
            if setUp:
                print(df + ": setUp....")
                setUp(proj)
            print(df + ": ok")
            StudyProjectEnv.saveProject(proj)
            # print(tempCommit)
            comeBackMaster(tempCommit)
            comeBackBranchCurr()
            return proj

        # "project-"+Git.toBrancheName(id)
        projectBranch = StudyProjectEnv.getProjectBranch(id, setUp, version)
        # print("projectBranch",projectBranch)
        if projectBranch is not None and Git.checkBranch(projectBranch):
            tempCommit = Git.goToBranch(projectBranch, no_reset=False)
            project = StudyProjectEnv.getProject(id, setUp)
            # setUpMd5=Utils.Hash.function_md5(setUp)
            if project is not None and project.setUp == "outdated":
                if tempCommitMaster:
                    if len(Git.getModified()) > 0:
                        warnings.warn(
                            "project {id} outdated(setUp) in branch {projectBranch} but there are Modifed files"
                        )
                        sys.exit()
                    comeBackMaster(tempCommit)
                return create_project()
            if project is not None:
                comeBackMaster(tempCommit)
                comeBackBranchCurr()
                print(f"Project '{id}' (v{project.v}) : loaded")
                return project
            comeBackMaster(tempCommit)
            comeBackBranchCurr()
            print(f"Project {id} not load !!!")
            return
            # load projectloaded")
            # return self.proj[id]
        return create_project()

    def getOrCreateStudy(self, id, setUp=None, data=None):
        if id in self.studies:
            print(f"Study '{id}' : loaded")
            return self.studies[id]
        df = " " * len(f"Study '{id}' ")
        print(f"Study '{id}' : creating...")
        self.studies[id] = Study(id, data=data)
        if setUp is not None:
            print(df + ": setUp....")
            setUp(self.studies[id])
            print(df + ": ok")


__all__ = ["StudyProject", "Data"]
