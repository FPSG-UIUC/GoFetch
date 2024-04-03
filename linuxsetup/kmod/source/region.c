#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include <asm/io.h>

#define NPAGES 16

static const char *tags[] = {
	"nGnRnE",
	"nGnRE",
	"nc",
	"normal",
};

static struct class *class;
static dev_t dev;
static struct cdev region_cdev[4];
static void *alloc_ptr;
static char *alloc_region;

static int
region_open(struct inode *inode, struct file *file)
{
	file->private_data = &inode->i_rdev;

	return 0;
}

static int
region_release(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t
region_read(struct file *file, char __user *buffer, size_t size, loff_t *offset)
{
	if (size > NPAGES * PAGE_SIZE) {
		size = NPAGES * PAGE_SIZE;
	}

	if (copy_to_user(buffer, alloc_region, size)) {
		return -EFAULT;
	}

	return size;
}

static ssize_t
region_write(struct file *file, const char __user *buffer, size_t size, loff_t *offset)
{
	if (size > NPAGES * PAGE_SIZE) {
		size = NPAGES * PAGE_SIZE;
	}

	if (copy_from_user(alloc_region, buffer, size)) {
		return -EFAULT;
	}

	return size;
}

static int
region_mmap(struct file *file, struct vm_area_struct *vma)
{
	dev_t *devt = file->private_data;
	unsigned long attr;
	long size = vma->vm_end - vma->vm_start;
	int rc;

	if (size > NPAGES * PAGE_SIZE) {
		return -EIO;
	}

	attr = MT_DEVICE_nGnRnE;

	switch (MINOR(*devt)) {
	case 0: attr = MT_DEVICE_nGnRnE; break;
	case 1: attr = MT_DEVICE_nGnRE; break;
	case 2: attr = MT_NORMAL_NC; break;
	case 3: attr = MT_NORMAL; break;
	}

	rc = remap_pfn_range(
		vma,
		vma->vm_start,
		virt_to_phys((void *)alloc_region) >> PAGE_SHIFT,
		size,
		__pgprot((pgprot_val(vma->vm_page_prot) & ~PTE_ATTRINDX_MASK) | PTE_ATTRINDX(attr))
	);

	if (rc) {
		pr_err("kmod: could not map memory");
		return rc;
	}

	return 0;
}

static const struct file_operations region_fops = {
	.owner = THIS_MODULE,
	.open = region_open,
	.release = region_release,
	.read = region_read,
	.write = region_write,
	.mmap = region_mmap,
};

static ssize_t
phys_addr_show(struct device *dev, struct device_attribute *attr, char *buffer)
{
	return sprintf(buffer, "%llx\n", virt_to_phys((void *)alloc_region));
}

DEVICE_ATTR_RO(phys_addr);

static ssize_t
virt_addr_show(struct device *dev, struct device_attribute *attr, char *buffer)
{
	return sprintf(buffer, "%lx\n", (uintptr_t)alloc_region);
}

DEVICE_ATTR_RO(virt_addr);

static struct attribute *dev_attrs[] = {
	&dev_attr_phys_addr.attr,
	&dev_attr_virt_addr.attr,

	NULL,
};

static struct attribute_group dev_attr_group = {
	.attrs = dev_attrs,
};

static const struct attribute_group *dev_attr_groups[] = {
	&dev_attr_group,
	NULL,
};

int
region_init(void)
{
	int rc;
	int i;

	alloc_ptr = kmalloc((NPAGES + 2) * PAGE_SIZE, GFP_KERNEL);

	if (alloc_ptr == NULL) {
		rc = -ENOMEM;
		pr_err("kmod: could not allocate memory");
		return rc;
	}

	alloc_region = (char *)PAGE_ALIGN(((unsigned long)alloc_ptr));

	for (i = 0; i < NPAGES * PAGE_SIZE; i += PAGE_SIZE) {
		SetPageReserved(virt_to_page(((unsigned long)alloc_region) + i));
	}

	class = class_create(THIS_MODULE, "mem_region");

	if (!class) {
		pr_err("kmod: could not allocate device class\n");
		goto err_unregister_chrdev_region;
	}

	rc = alloc_chrdev_region(&dev, 0, 4, "mem_region");

	if (rc) {
		pr_err("kmod: major number allocation failed\n");
		goto err_kfree;
	}

	for (i = 0; i < 4; ++i) {
		cdev_init(region_cdev + i, &region_fops);
		rc = cdev_add(region_cdev + i, MKDEV(MAJOR(dev), i), 1);

		if (rc) {
			pr_err("kmod: could not add device\n");
			goto err_unregister_chrdev_region;
		}

		if (!device_create_with_groups(
			class,
			NULL,
			MKDEV(MAJOR(dev), i),
			NULL,
			dev_attr_groups,
			"mem_region_%s",
			tags[i])) {
			pr_err("kmod: could not create /dev/mem_region_%s", tags[i]);
		}
	}

	return 0;

err_unregister_chrdev_region:
	unregister_chrdev_region(dev, 4);
err_kfree:
	kfree(alloc_ptr);
	return rc;
}

void
region_exit(void)
{
	int i;

	for (i = 0; i < 4; ++i) {
		cdev_del(region_cdev + i);
		device_destroy(class, MKDEV(MAJOR(dev), i));
	}

	unregister_chrdev_region(dev, 4);

	for (i = 0; i < NPAGES * PAGE_SIZE; i += PAGE_SIZE) {
		ClearPageReserved(virt_to_page(((unsigned long)alloc_region) + i));
	}

	class_destroy(class);
	kfree(alloc_ptr);
}
