#ifndef DEVICE_REGISTER_H
#define DEVICE_REGISTER_H

#include <linux/device.h>

struct device_info {
    struct class* cls;
    struct device* chardev;
    int major;
    umode_t mode;
    char name[128];
};

static char* devreg_devnode(const struct device *dev, umode_t *mode) {
    const struct device_info* info = dev_get_drvdata(dev);

    if (!info || !mode)
        return 0;

    *mode = info->mode;
    return 0;
}

static void devreg_class_create_release(const struct class *cls) {
    pr_debug("%s called for %s\n", __func__, cls->name);
    kfree(cls);
}

static struct class *devreg_class_create(const char *name, char* (*devnode)(const struct device*, umode_t*)) {
    struct class *cls;
    int retval;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    static struct lock_class_key key;
#endif

    cls = kzalloc(sizeof(*cls), GFP_KERNEL);
    if (!cls) {
        retval = -ENOMEM;
        goto error;
    }

    cls->name = name;
    cls->class_release = (void*) devreg_class_create_release;
    cls->devnode = (void*) devnode;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    retval = class_register(cls);
#else
    cls->owner = THIS_MODULE;
    retval = __class_register(cls, &key);
#endif
    if (retval)
        goto error;

    return cls;

    error:
        kfree(cls);
    return ERR_PTR(retval);
}

static int create_chardev(struct device_info* info, const struct file_operations* fops, const char* name, umode_t mode) {
    if (strlen(name) >= sizeof(info->name))
        return -EINVAL;
    strncpy(info->name, name, sizeof(info->name));
    info->mode = mode;

    info->major = register_chrdev(0, name, fops);
    if (info->major < 0) {
        printk(KERN_ERR "Failed to register character device\n");
        return info->major;
    }

    info->cls = devreg_class_create(name, devreg_devnode);

    info->chardev = device_create(info->cls, NULL, MKDEV(info->major, 0), info, name);
    if (IS_ERR(info->chardev))
        return -EFAULT;

    return 0;
}

static void remove_chardev(struct device_info* info) {
    device_destroy(info->cls, MKDEV(info->major, 0));
    class_destroy(info->cls);
    unregister_chrdev(info->major, info->name);
    memset(info, 0, sizeof(*info));
}

#endif