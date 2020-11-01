import os
import sys
import tempfile

import git
from dvc import main


class Utils:
    class RE:
        @staticmethod
        def captureValueInLine(text, pattern, sep=":"):
            import re

            return re.findall(
                f"^.*{pattern}{sep}(.+)$", text, flags=re.MULTILINE
            )[0].strip()

    class Hash:
        @staticmethod
        def md5(string):
            import hashlib

            return hashlib.md5(string.encode()).hexdigest()

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

    class Shell:
        @staticmethod
        def command(commandString):
            import shlex
            import subprocess

            process = subprocess.Popen(
                shlex.split(commandString), stdout=subprocess.PIPE, shell=False
            )
            output, error = process.communicate()
            return Struct(
                **{
                    "output": output,
                    "error": error,
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
        def tmp_delete(filename):
            file = TMP_FILE()
            file.filename = filename
            file.delete()

    class Dir:
        @staticmethod
        def mk(dir, p=None):
            os.mkdir(dir)

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


class Struct:
    def __init__(self, **entries):
        self.__dict__.update(entries)

    def __str__(self):
        a = ""
        for i in self.__dict__.keys():
            a += f"{i} :"
            a += f"\n\t{self.__dict__[i]}\n"
        return a


class Git:
    installed = False

    @staticmethod
    def check_installed():
        return Git.installed or os.path.isdir(os.getcwd() + "/.git")

    @staticmethod
    def install(add=True, commit=True, message="git installed"):
        print("\tset up Git...")
        g = git.cmd.Git(os.getcwd())
        g.init()
        Utils.Shell.command("touch .gitignore")
        if add:
            Git.add([".gitignore"])
        if commit:
            StudyProjectEnv.commit(message)
        print("\tGit initialized")
        Git.installed = True

    @staticmethod
    def addTag(name, desc):
        g = git.cmd.Git(os.getcwd())
        g.tag(["-a", f"'{name}'", "-m", f"'{desc}'"])

    @staticmethod
    def getBranch():
        rep = Utils.Shell.command(f"git branch --show-current")
        if rep.error:
            raise Exception(rep)
        return rep.output.strip().decode("utf-8")

    @staticmethod
    def deleteBranch(name):
        Utils.Shell.command(f"git branch -d {name}")

    @staticmethod
    def checkBranch(name):
        rep = Utils.Shell.command(f"git branch  --list '{name}' | tr -d ' '")
        if rep.error:
            raise Exception(rep)
        branch = rep.output
        return len(branch) > 0

    @staticmethod
    def addBranch(name, checkout=True):
        if Git.checkBranch(name):
            return
        if checkout:
            g = git.cmd.Git(os.getcwd())
            g.checkout(["-b", f"{name}"])
        else:
            g = git.cmd.Git(os.getcwd())
            g.branch([f"{name}"])

    @staticmethod
    def getNoHooks():
        return "-c core.hooksPath=/dev/null"

    @staticmethod
    def goToBranch(name, no_hooks=False):
        # g = git.cmd.Git(os.getcwd())
        # g.checkout([f"{name}"])
        hooks = Git.getNoHooks() if no_hooks else ""
        Utils.Shell.command(f"git {hooks} checkout {name}")

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
            rep = Utils.Shell.command(
                f"git {commiter} commit {author} -m '{message}'"
            )
            if rep.error:
                raise Exception(rep.error)
            # if rep.output:
            #   print(rep.output,rep.commandString)
            return
        g = git.cmd.Git(os.getcwd())
        g.commit([author, "-m", f"'{message}'"])

    @staticmethod
    def merge(branch, no_ff=True, message="", author=""):
        if len(author) > 0:
            commiter = Git.getConfigUser(author)
            message = message.replace("'", '"')
            messageN = f"-m '{message}'"
            rep = Utils.Shell.command(
                f"git {commiter} merge {Utils.ifelse(no_ff,'--no-ff')} {Utils.ifelse(message,messageN)} {branch}"
            )
            if rep.error:
                print(rep)
                raise Exception(rep.error)
            # if rep.output:
            #   print(rep.output, rep.commandString)
            return
        g = git.cmd.Git(os.getcwd())
        g.merge([Utils.ifelse(no_ff, "--no-ff"), branch])

    @staticmethod
    def add(listToAdd):
        g = git.cmd.Git(os.getcwd())
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
        return Utils.Shell.command(
            f"git config {Utils.ifelse(globally,'--global')} {Utils.ifelse(v is None and not remove,'--get')} {Utils.ifelse(remove,'--unset')} {k} {Utils.ifelse(v is not None, v)}"
        )


class Dvc:
    installed = False
    author = "DvcBot <DvcBot@DvcBot.DvcBot>"

    @staticmethod
    def check_installed():
        return Dvc.installed or os.path.isdir(os.getcwd() + "/.dvc")

    @staticmethod
    def install():
        print("\tset up dvc...")
        k = main.main(["init", "--quiet"])
        Dvc.config("core.autostage", "true")
        Git.add([".dvc/config"])
        main.main(["install"])
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
        df.to_csv(file.get_filename("csv"), index=index)
        if len(path) > 0:
            path = path + "/"
        main.main(
            [
                "add",
                "--external",
                "--file",
                f"{path}{name}.{ext}.dvc",
                file.filename,
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


class StudyProjectEnv:
    installed = False
    path = ".study_project"
    step = 0
    prefixe = "study_project : "
    default_branch = "study_project_set_up"
    data_path = "data"

    @staticmethod
    def check_installed():
        return StudyProjectEnv.installed or os.path.isdir(
            os.getcwd() + "/" + StudyProjectEnv.path
        )

    @staticmethod
    def install():
        print("\tset up study_project...")
        os.mkdir(StudyProjectEnv.path)
        os.mkdir(StudyProjectEnv.data_path)
        os.mkdir(StudyProjectEnv.path + "/projects")
        os.mkdir(StudyProjectEnv.path + "/studies")
        os.mkdir(StudyProjectEnv.path + "/data")
        Utils.Shell.command(f"touch {StudyProjectEnv.path}/.gitignore")
        print("\tstudy_project initialized")
        StudyProjectEnv.installed = True
        Git.add([StudyProjectEnv.path])
        StudyProjectEnv.commit("study_project installed")

    @staticmethod
    def addBranch(name):
        brName = f"{StudyProjectEnv.step}-{name}"
        Git.addBranch(brName)
        StudyProjectEnv.step += 1
        return brName

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
                return False
            install = True
            print("Set Up Study Project ....")
            if not Git.check_installed():
                # StudyProjectEnv.check_init()
                Git.install()
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
                Git.goToBranch("master", no_hooks=True)
                StudyProjectEnv.merge(currBranche, message="set-up")
                Git.deleteBranch(currBranche)
            print("Study Project OK")
            return True
        return True

    @staticmethod
    def check_init():
        rep = Utils.Shell.command("git branch")
        if rep.error:
            raise Exception(rep.error)
        if len(rep.output) == 0:
            Utils.Shell.command("touch .initial_commit")
            Git.add([".initial_commit"])
            Git.commit()

    @staticmethod
    def goToBranch(name):
        Git.goToBranch()

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
    def saveData(data, dataHash):
        projPath = StudyProjectEnv.path + "/data"
        if not Utils.File.exist(projPath + "/" + dataHash):
            StudyProjectEnv.addData(data.train, data.fileName + "_train")
            StudyProjectEnv.addData(data.test, data.fileName + "_test")
            StudyProjectEnv.addData(data.target, data.fileName + "_target")
            fileStr = f"""
id: {data.id}
comment: {data.comment}
train: {data.md5_train}
test: {data.md5_test}
target: {data.md5_target}
"""
            Utils.File.write(fileStr, projPath + "/" + dataHash)

    @staticmethod
    def forgotData(dataHash):
        pass

    @staticmethod
    def saveProject(project):
        projPath = (
            StudyProjectEnv.path
            + "/projects/"
            + Git.toBrancheName(project.id, sep="_")
        )
        try:
            Utils.Dir.mk(projPath)
        except Exception as e:
            print(e)
        # os.mkdir(StudyProjectEnv.path+"/project/"+Git.toBrancheName(project.id,sep="_")+"/studies")
        # os.mkdir(StudyProjectEnv.path+"/project/"+Git.toBrancheName(project.id,sep="_")+"/data")

        dataHash = {data.get_hash(): data.id for data in project.data.values()}
        dataHash = dict(sorted(dataHash.items(), key=lambda a: a[0]))
        dataHashDico = dataHash

        dataHashStr = "\n".join(dataHash.keys())
        if not Utils.File.exist(f"{projPath}/data"):
            lastDataHashStr = ""
        else:
            lastDataHashStr = Utils.File.read(f"{projPath}/data")

        if lastDataHashStr != dataHashStr:
            Utils.File.write(dataHashStr, filename=f"{projPath}/data")
            lastDataHash = set(lastDataHashStr.split("\n"))
            dataHash = set(dataHash.keys())
            newData = dataHash - lastDataHash
            pastData = lastDataHash - dataHash
            for i in newData:
                StudyProjectEnv.saveData(project.data[dataHashDico[i]], i)
            for i in pastData:
                StudyProjectEnv.forgotData(i)

        # studiesHash=[study.get_hash() for study in project.studies.values()]
        # Utils.File.write("\n".join(dataHash),filename=f"{projPath}/studies")

        # hash([project.data,project.studies])
        # StudyProjectEnv.create_project()


class Data:
    def setData(self, id, train, test, target, comment=""):
        # check is pandas df, series
        self.id = id
        self.train = train
        self.test = test
        self.target = target
        self.comment = comment

        # maybe -> StudyProjectEnv should do that
        brName = Git.toBrancheName(id)
        self.fileName = Git.toBrancheName(id, sep="_")
        fileName = self.fileName
        (new, md5_train) = StudyProjectEnv.addData(
            self.train, f"{fileName}_train"
        )
        (new2, md5_target) = StudyProjectEnv.addData(
            self.target, f"{fileName}_target"
        )
        (new3, md5_test) = StudyProjectEnv.addData(
            self.test, f"{fileName}_test"
        )
        self.md5_target = md5_target
        self.md5_train = md5_train
        self.md5_test = md5_test
        if new or new2 or new3:
            StudyProjectEnv.commit(f"add Data '{id}'")
        # StudyProjectEnv.addBranch(f"add-data-{brName}")

    def get_hash(data):
        fileStr = f"""
id: {data.id}
comment: {data.comment}
train: {data.md5_train}
test: {data.md5_test}
target: {data.md5_target}
"""
        return Utils.Hash.md5(fileStr)


class Study:
    """docstring for Study"""

    def __init__(self, id, data=None):
        self.id = id
        self.data = data


class StudyProject:
    proj = {}

    def __init__(self, id):
        self.data = {}
        self.studies = {}
        self.id = id

    def saveData(self, id, train, test, target, comment=""):
        if id in self.data:
            print(f"\tData '{id}' : loaded ")
            return self.data[id]
        print(f"\tData '{id}' : creating... ")
        data = Data()
        data.setData(id, train, test, target, comment)
        self.data[id] = data
        print(f"\tData '{id}' : ok ")
        StudyProjectEnv.saveProject(self)

    @classmethod
    def getOrCreate(self, id, setUp, recreate=False):
        if not StudyProjectEnv.check_all_installed():
            return
        # "project-"+Git.toBrancheName(id)
        if Git.checkBranch("project-" + Git.toBrancheName(id)):
            Git.goToBranch("project-" + Git.toBrancheName(id))
            # load project
            return
        if id in self.proj:
            print(f"Project '{id}' : loaded")
            return self.proj[id]
        Git.addBranch("project-" + Git.toBrancheName(id))
        df = " " * len(f"Project '{id}' ")
        print(f"Project '{id}' : creating...")
        self.proj[id] = self(id)
        print(df + ": setUp....")
        setUp(self.proj[id])
        print(df + ": ok")
        StudyProjectEnv.saveProject(self.proj[id])

    def getOrCreateStudy(id, setUp=None, data=None):
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
