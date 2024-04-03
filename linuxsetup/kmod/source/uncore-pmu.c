#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/sysfs.h>
#include <linux/cdev.h>

#include <asm/cpu.h>
#include <asm/io.h>

#define UPMCR0_OFFSET  0x4180

#define UPMESR0_OFFSET 0x41b0
#define UPMESR1_OFFSET 0x41b8

#define UPMECM0_OFFSET 0x4190
#define UPMECM1_OFFSET 0x4198
#define UPMECM2_OFFSET 0x41a0
#define UPMECM3_OFFSET 0x41a8

#define UPMC0_OFFSET   0x4100
#define UPMC1_OFFSET   0x4248
#define UPMC2_OFFSET   0x4110
#define UPMC3_OFFSET   0x4250
#define UPMC4_OFFSET   0x4120
#define UPMC5_OFFSET   0x4258
#define UPMC6_OFFSET   0x4130
#define UPMC7_OFFSET   0x4260
#define UPMC8_OFFSET   0x4140
#define UPMC9_OFFSET   0x4268
#define UPMC10_OFFSET  0x4150
#define UPMC11_OFFSET  0x4270
#define UPMC12_OFFSET  0x4160
#define UPMC13_OFFSET  0x4278
#define UPMC14_OFFSET  0x4170
#define UPMC15_OFFSET  0x4280

static struct class *class;
static dev_t dev;
static struct cdev cdev[2];
static unsigned long base[2] = {
	0x210e40000,
	0x211e40000,
};
static void *mappings[2] = {
	NULL,
};

static size_t
cluster_id(void)
{
	uint64_t value;

	asm volatile("mrs %0, mpidr_el1" : "=r" (value));

	return (value >> 8) & 0xff;
}

static int
is_remote(struct device *device)
{
	return cluster_id() != MINOR(device->devt);
}

static int
dev_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int
dev_release(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t
dev_read(struct file *file, char __user *buffer, size_t count, loff_t *offset)
{
	return 0;
}

static ssize_t
dev_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset)
{
	return 0;
}

struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = dev_open,
	.release = dev_release,
	.read = dev_read,
	.write = dev_write,
};

#define UPM_ATTR_RW(name, reg, offset) \
static ssize_t \
name ## _show(struct device *dev, struct device_attribute *attr, char *buffer) \
{ \
	uint64_t value; \
	\
	if (is_remote(dev)) { \
		uint64_t *mapping = (uint64_t *)((char *)dev_get_drvdata(dev) + offset); \
		\
		value = *mapping; \
	} else { \
		asm volatile("mrs %0, " reg : "=r" (value)); \
	} \
	\
	return sprintf(buffer, "%llx\n", value); \
} \
\
static ssize_t \
name ## _store(struct device *dev, struct device_attribute *attr, const char *buffer, size_t count) \
{ \
	uint64_t value; \
	\
	sscanf(buffer, "%llx", &value); \
	\
	if (is_remote(dev)) { \
		uint64_t *mapping = (uint64_t *)((char *)dev_get_drvdata(dev) + offset); \
		\
		*mapping = value; \
	} else { \
		asm volatile( \
			"msr " reg ", %0\n\t" \
			"isb\n\t" \
			:: "r" (value) \
		); \
	} \
	\
	return count; \
} \
\
DEVICE_ATTR_RW(name);

UPM_ATTR_RW(upmcr0, "S3_7_c15_c0_4", UPMCR0_OFFSET);

UPM_ATTR_RW(upmesr0, "S3_7_c15_c1_4", UPMESR0_OFFSET);
UPM_ATTR_RW(upmesr1, "S3_7_c15_c11_5", UPMESR1_OFFSET);

UPM_ATTR_RW(upmecm0, "S3_7_c15_c3_4", UPMECM0_OFFSET);
UPM_ATTR_RW(upmecm1, "S3_7_c15_c4_4", UPMECM1_OFFSET);
UPM_ATTR_RW(upmecm2, "S3_7_c15_c8_5", UPMECM2_OFFSET);
UPM_ATTR_RW(upmecm3, "S3_7_c15_c9_5", UPMECM3_OFFSET);

UPM_ATTR_RW(upmc0,  "S3_7_c15_c7_4",  UPMC0_OFFSET);
UPM_ATTR_RW(upmc1,  "S3_7_c15_c8_4",  UPMC1_OFFSET);
UPM_ATTR_RW(upmc2,  "S3_7_c15_c9_4",  UPMC2_OFFSET);
UPM_ATTR_RW(upmc3,  "S3_7_c15_c10_4", UPMC3_OFFSET);
UPM_ATTR_RW(upmc4,  "S3_7_c15_c11_4", UPMC4_OFFSET);
UPM_ATTR_RW(upmc5,  "S3_7_c15_c12_4", UPMC5_OFFSET);
UPM_ATTR_RW(upmc6,  "S3_7_c15_c13_4", UPMC6_OFFSET);
UPM_ATTR_RW(upmc7,  "S3_7_c15_c14_4", UPMC7_OFFSET);

UPM_ATTR_RW(upmc8,  "S3_7_c15_c0_5",  UPMC8_OFFSET);
UPM_ATTR_RW(upmc9,  "S3_7_c15_c1_5",  UPMC9_OFFSET);
UPM_ATTR_RW(upmc10, "S3_7_c15_c2_5",  UPMC10_OFFSET);
UPM_ATTR_RW(upmc11, "S3_7_c15_c3_5",  UPMC11_OFFSET);
UPM_ATTR_RW(upmc12, "S3_7_c15_c4_5",  UPMC12_OFFSET);
UPM_ATTR_RW(upmc13, "S3_7_c15_c5_5",  UPMC13_OFFSET);
UPM_ATTR_RW(upmc14, "S3_7_c15_c6_5",  UPMC14_OFFSET);
UPM_ATTR_RW(upmc15, "S3_7_c15_c7_5",  UPMC15_OFFSET);

static struct attribute *dev_attrs[] = {
	&dev_attr_upmcr0.attr,

	&dev_attr_upmesr0.attr,
	&dev_attr_upmesr1.attr,

	&dev_attr_upmecm0.attr,
	&dev_attr_upmecm1.attr,
	&dev_attr_upmecm2.attr,
	&dev_attr_upmecm3.attr,

	&dev_attr_upmc0.attr,
	&dev_attr_upmc1.attr,
	&dev_attr_upmc2.attr,
	&dev_attr_upmc3.attr,
	&dev_attr_upmc4.attr,
	&dev_attr_upmc5.attr,
	&dev_attr_upmc6.attr,
	&dev_attr_upmc7.attr,
	&dev_attr_upmc8.attr,
	&dev_attr_upmc9.attr,
	&dev_attr_upmc10.attr,
	&dev_attr_upmc11.attr,
	&dev_attr_upmc12.attr,
	&dev_attr_upmc13.attr,
	&dev_attr_upmc14.attr,
	&dev_attr_upmc15.attr,

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
uncore_pmu_init(void)
{
	int rc;
	int i;
	int major;

	rc = alloc_chrdev_region(&dev, 0, 2, "uncore_pmu");

	if (rc) {
		pr_err("kmod: major number allocation failed\n");
		return rc;
	}

	class = class_create(THIS_MODULE, "uncore_pmu_class");

	if (!class) {
		pr_err("kmod: could not allocate device class\n");
		goto err_unregister_chrdev_region;
	}

	major = MAJOR(dev);

	for (i = 0; i < 2; ++i) {
		cdev_init(cdev + i, &fops);
		rc = cdev_add(cdev + i, MKDEV(major, i), 1);

		if (rc) {
			pr_err("kmod: could not add cdev %d\n", i);
			goto err_class_destroy;
		}

		mappings[i] = ioremap_np(base[i], 0x10000);

		if (!mappings[i]) {
			pr_err("kmod: could not map 0x%lx\n", base[i]);
		}

		if (!device_create_with_groups(
			class,
			NULL,
			MKDEV(major, i),
			mappings[i],
			dev_attr_groups,
			"uncore_pmu%d",
			i)) {
			pr_err("kmod: could not create /dev/uncore_pmu%d\n", i);
		}
	}

	return 0;

err_class_destroy:
	class_destroy(class);
err_unregister_chrdev_region:
	unregister_chrdev_region(dev, 2);
	return rc;
}

void
uncore_pmu_exit(void)
{
	int major;
	int i;

	major = MAJOR(dev);

	for (i = 0; i < 2; ++i) {
		cdev_del(cdev + i);
		device_destroy(class, MKDEV(major, i));

		if (mappings[i]) {
			iounmap(mappings[i]);
		}
	}

	class_destroy(class);
	unregister_chrdev_region(dev, 2);
}
