#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/sched/mm.h>
#include <linux/expose_pgtbl.h>

#define OFFSET_MAX	0xFFF
#define vadd_iter	0x1000
#define BUF_SIZE	4096

struct mm_struct *get_task_mm_expose(struct task_struct *task)
{
	struct mm_struct *mm;

	task_lock(task);
	mm = task->mm;
	if (mm) {
		if (task->flags & PF_KTHREAD)
			mm = NULL;
		else
			mmget(mm);
	}
	task_unlock(task);
	return mm;
}


/*
 * Investigate the page table layout.
 *
 * The page table layout varies over different architectures (eg. x86 vs arm).
 * It also changes with the change of system configuration.  
 *
 * You need to implement a system call to get the page table layout information
 * of the current system. Use syscall number 441.
 * @pgtbl_info : user address to store the related infomation; note the
 * normal page size can be inferred from the page_shift.
 */
SYSCALL_DEFINE1(get_pagetable_layout, struct pagetable_layout_info __user *, pgtbl_info)
{
	// if(!pgtbl_info)
	// 	return -EINVAL;
	struct pagetable_layout_info tmp;
	tmp.pgdir_shift = PGDIR_SHIFT;
	tmp.p4d_shift = P4D_SHIFT;
	tmp.pud_shift = PUD_SHIFT;
	tmp.pmd_shift = PMD_SHIFT;
	tmp.page_shift = PAGE_SHIFT;
	if(copy_to_user(pgtbl_info, &tmp, sizeof(struct pagetable_layout_info)))
		return -EFAULT;
	return 0;
}

/*struct expose_pgtbl_args {
	unsigned long fake_pgd;
	unsigned long fake_p4ds;
	unsigned long fake_puds;
	unsigned long fake_pmds;
	unsigned long page_table_addr;
	unsigned long begin_vaddr;
	unsigned long end_vaddr;
};*/

SYSCALL_DEFINE2(expose_page_table, pid_t, pid, struct expose_pgtbl_args __user *, args)
{
	struct expose_pgtbl_args local_args;
	struct task_struct *from_task = current;
	struct mm_struct *from_mm;
	struct mm_struct *to_mm;
	struct vm_area_struct *from_vma;
	struct vm_area_struct *to_mm;
	int result = 0;

	if (!args)
		return -EINVAL;
	if (copy_from_user(&local_args, args, sizeof(struct expose_pgtbl_args)))
		return -EFAULT;

	if (pid != -1)
		from_task = find_task_by_vpid(pid);
	if (!from_task || !current)
		return -ESRCH;
	from_mm = from_task->mm;
	to_mm = current->mm;

	/* TODO: copy the page tables */

	/* get the VMA from begin_vaddr to end_vaddr to map */
	from_vma = find_vma(from_mm, local_args.begin_vaddr);

	/* TODO using from_vma, get the physical PFN to map from */
	//	unsigned long start = from_vma->vm_start;

	/* get the VMA to map into */
	to_vma = find_vma(to_mm, local_args.page_table_addr);

	/* TODO do the mapping from the VMA to page_table_addr*/
	result = remap_pfn_range(to_vma, PAGE_ALIGN(local_args.page_table_addr),
				 ..., PAGE_SIZE, to_vma->vm_page_prot);


	/* struct task_struct *p_task; */
	/* struct mm_struct *mm; */
	/* struct expose_pgtbl_args *buf; */
	/* u64 virtual_add_begin = 0; */
	/* u64 virtual_add_end = OFFSET_MAX; */
	/* u64 i = 0; */
	/* struct vm_area_struct *vma; */
	
	/* if (!args) */
	/* 	return -EINVAL; */

	/* /\* kmalloc because size is large *\/ */
	/* buf = kmalloc(BUF_SIZE*sizeof(struct expose_pgtbl_args), GFP_KERNEL); */
	
	/* if (!buf) */
	/* 	return -ENOMEM; */

	/* rcu_read_lock(); */
	/* p_task = (pid == -1) ? current : find_task_by_vpid(pid); */
	/* if (!p_task) { */
	/* 	rcu_read_unlock(); */
	/* 	return -ESRCH; */
	/* } */
	/* get_task_struct(p_task); */
	/* rcu_read_unlock(); */

	/* mm = get_task_mm_expose(p_task); */
	
	/* if (!mm) */
	/* 	return -ESRCH; */

	/* for (vma = mm->mmap; vma; vma = vma->vm_next) { */
		
	/* 	if (i < BUF_SIZE) { */
	
	/* 	buf[i].begin_vaddr	= vma->vm_start; */
	/* 	buf[i].end_vaddr	= vma->vm_end; */
	/* 	buf[i].fake_pgd		= 0; */
	/* 	buf[i].fake_p4ds	= 0; */
	/* 	buf[i].fake_puds	= 0; */
	/* 	buf[i].fake_pmds	= 0; */
	/* 	buf[i].page_table_addr	= 0; */
		
	/* 	u64 addr = vma->vm_start; */
		
	/* 	pgd_t *pgd		= pgd_offset(mm, addr); */
		
	/* 	if (!pgd) { */
	/* 		buf[i].fake_pgd	= pgd->pgd; */
	/* 		p4d_t *p4d	= p4d_offset(pgd, addr); */
			
	/* 		if (!p4d) { */
	/* 			buf[i].fake_p4ds= p4d->pgd.pgd; */
	/* 			pud_t *pud	= pud_offset(p4d, addr); */
				
	/* 			if (!pud) { */
	/* 				buf[i].fake_puds= pud->pud; */
	/* 				pmd_t *pmd	= pmd_offset(pud, addr); */
				
	/* 				if (!pmd) { */
	/* 					buf[i].fake_pmds= pmd->pmd; */
	/* 					pte_t *pte	= pte_offset_map(pmd, addr); */
						
	/* 					if (!pte) */
	/* 						buf[i].page_table_addr	= pte->pte; */
	/* 				} */
	/* 			} */
	/* 		} */
	/* 	} */
	/* 	} */
		
	/* 	i++; */
	/* } */

	
	/* if (copy_to_user(args, buf, BUF_SIZE*sizeof(struct expose_pgtbl_args))) */
	/* 	return -EFAULT; */
	
	/* kfree(buf); */
	
	/* return i; */
}

SYSCALL_DEFINE1(get_pa_contents, long, phys_addr)
{
	/* This may need to be tested and revised after 442 is done for further testing */
	return *((int *)__va(phys_addr));
	//return 0;
}
